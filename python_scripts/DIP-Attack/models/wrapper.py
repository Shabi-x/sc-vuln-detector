"""
Model wrapper: training pipeline + single-sample inference with caching.

Provides a unified ``model(source_code) → 0/1`` interface for all four
victim architectures, plus ``model.predict_score(code) → float`` for
gradient-estimated position selection.
"""

import copy, math, hashlib
from typing import Dict, List, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset

from models.tokenizer import SolidityTokenizer
from models.features import (
    structural_features,
    vuln_keyword_features,
    name_features,
    build_call_graph_features,
    expert_pattern_features,
)
from models.architectures import (
    AMEDetector,
    ConvMHSADetector,
    GCNProxyDetector,
    ClearDetector,
)

MAX_INPUT_LEN = 512
MODEL_NAMES = ["AME", "ConvMHSA", "GPSCVul", "Clear"]

# 这些受害模型包含的 Transformer/图结构算子在 macOS MPS 上并不稳定，
# 为保证 AME/GPSCVul/ConvMHSA/Clear 都能稳定接入系统评估流程，这里统一优先用 CUDA，
# 否则退回 CPU，而不走 MPS。
DEVICE = (
    torch.device("cuda") if torch.cuda.is_available() else
    torch.device("cpu")
)


# ─────────────────────────────────────────────────────────────────────
# Base class
# ─────────────────────────────────────────────────────────────────────

class VictimModelBase:
    def __init__(self, name: str, vuln_type: str):
        self.name = name
        self.vuln_type = vuln_type

    def predict(self, source_code: str) -> int:
        raise NotImplementedError

    def __call__(self, source_code: str) -> int:
        return self.predict(source_code)

    def get_name(self) -> str:
        return self.name


# ─────────────────────────────────────────────────────────────────────
# PyTorch wrapper
# ─────────────────────────────────────────────────────────────────────

class PyTorchVictimModel(VictimModelBase):
    ARCH_MAP = {
        "AME": AMEDetector,
        "ConvMHSA": ConvMHSADetector,
        "GPSCVul": GCNProxyDetector,
        "Clear": ClearDetector,
    }
    NEEDS_GRAPH = {"AME", "GPSCVul"}

    def __init__(self, name: str, vuln_type: str):
        super().__init__(name, vuln_type)
        self.tokenizer: Optional[SolidityTokenizer] = None
        self.net: Optional[nn.Module] = None
        self.trained = False

    # ── feature helpers ──────────────────────────────────────────────

    def _extra(self, code: str) -> np.ndarray:
        return np.concatenate([
            structural_features(code),
            vuln_keyword_features(code, self.vuln_type),
            name_features(code),
        ])

    def _graph(self, code: str) -> np.ndarray:
        return build_call_graph_features(code)

    def _pattern(self, code: str) -> np.ndarray:
        return expert_pattern_features(code, self.vuln_type)

    @property
    def extra_dim(self) -> int:
        return 10 + 15 + 32  # structural + keyword + name

    # ── training ─────────────────────────────────────────────────────

    def train_model(self, train_codes: List[str], train_labels: List[int],
                    epochs: int = 30, lr: float = 1e-3, batch_size: int = 32) -> float:
        self.tokenizer = SolidityTokenizer(max_vocab=3000, max_len=MAX_INPUT_LEN)
        self.tokenizer.build_vocab(train_codes)
        ids = self.tokenizer.encode_batch(train_codes)
        extras = torch.tensor(
            np.array([self._extra(c) for c in train_codes]), dtype=torch.float32
        )
        labels_t = torch.tensor(train_labels, dtype=torch.float32)

        arch_cls = self.ARCH_MAP[self.name]
        if self.name in self.NEEDS_GRAPH:
            graphs = torch.tensor(
                np.array([self._graph(c) for c in train_codes]), dtype=torch.float32
            )
            patterns = torch.tensor(
                np.array([self._pattern(c) for c in train_codes]), dtype=torch.float32
            )
            self.net = arch_cls(
                vocab_size=self.tokenizer.vocab_size, extra_dim=self.extra_dim
            ).to(DEVICE)
            ds = TensorDataset(ids, extras, graphs, patterns, labels_t)
        else:
            self.net = arch_cls(
                vocab_size=self.tokenizer.vocab_size, extra_dim=self.extra_dim
            ).to(DEVICE)
            ds = TensorDataset(ids, extras, labels_t)

        # Contrastive pre-training for Clear
        if self.name == "Clear":
            self._contrastive_pretrain(ids, labels_t, epochs=2, lr=1e-4)

        opt = torch.optim.Adam(self.net.parameters(), lr=lr, weight_decay=1e-4)
        n_pos = sum(train_labels)
        n_neg = len(train_labels) - n_pos
        pos_weight = torch.tensor(
            [n_neg / max(n_pos, 1)], dtype=torch.float32
        ).to(DEVICE)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        dl = DataLoader(
            ds, batch_size=batch_size, shuffle=True,
            drop_last=(len(ds) > batch_size),
        )

        self.net.train()
        best_loss = float('inf'); patience, no_improve = 8, 0
        for ep in range(epochs):
            total_loss = 0.0
            for batch in dl:
                if self.name in self.NEEDS_GRAPH:
                    bid, eid, gid, pid, lid = [b.to(DEVICE) for b in batch]
                    logits = self.net(bid, eid, gid, pid)
                else:
                    bid, eid, lid = [b.to(DEVICE) for b in batch]
                    logits = self.net(bid, eid)
                loss = criterion(logits, lid)
                opt.zero_grad(); loss.backward(); opt.step()
                total_loss += loss.item()
            avg = total_loss / max(len(dl), 1)
            if avg < best_loss - 1e-4:
                best_loss = avg; no_improve = 0
            else:
                no_improve += 1
            if no_improve >= patience:
                break

        self.net.eval(); self.trained = True

        # Compute training accuracy
        with torch.no_grad():
            if self.name in self.NEEDS_GRAPH:
                logits = self.net(
                    ids.to(DEVICE), extras.to(DEVICE),
                    graphs.to(DEVICE), patterns.to(DEVICE),
                )
            else:
                logits = self.net(ids.to(DEVICE), extras.to(DEVICE))
            preds = (logits > 0).long().cpu().numpy()
            acc = (preds == np.array(train_labels)).mean() * 100
        return acc

    def _contrastive_pretrain(self, ids, labels, epochs=5, lr=5e-4,
                              batch_size=64):
        """CLIP-style contrastive pre-training for Clear."""
        opt = torch.optim.Adam(self.net.parameters(), lr=lr)
        ds = TensorDataset(ids, labels)
        dl = DataLoader(ds, batch_size=batch_size, shuffle=True)
        self.net.train()
        for ep in range(epochs):
            for bid, lid in dl:
                bid, lid = bid.to(DEVICE), lid.to(DEVICE)
                if bid.shape[0] < 4:
                    continue
                mask_prob = 0.15
                mask = torch.bernoulli(
                    torch.full_like(bid.float(), mask_prob)
                ).bool()
                bid2 = bid.clone(); bid2[mask] = 1  # UNK
                loss = self.net.contrastive_loss(bid, bid2, lid)
                if loss.item() > 0:
                    opt.zero_grad(); loss.backward(); opt.step()

    # ── inference (CPU, cached) ──────────────────────────────────────

    @torch.no_grad()
    def _forward(self, code: str) -> float:
        if not hasattr(self, '_fwd_cache'):
            self._fwd_cache = {}
        h = hashlib.md5(code.encode()).hexdigest()
        if h in self._fwd_cache:
            return self._fwd_cache[h]

        feat_code = code[:20000] if len(code) > 20000 else code
        dev = torch.device('cpu')
        with torch.inference_mode():
            ids = torch.tensor(
                [self.tokenizer.encode(code)], dtype=torch.long, device=dev
            )
            ext = torch.tensor(
                [self._extra(feat_code)], dtype=torch.float32, device=dev
            )
            if not hasattr(self, '_cpu_net'):
                self._cpu_net = copy.deepcopy(self.net).cpu().eval()
            if self.name in self.NEEDS_GRAPH:
                g = torch.tensor(
                    [self._graph(feat_code)], dtype=torch.float32, device=dev
                )
                p = torch.tensor(
                    [self._pattern(feat_code)], dtype=torch.float32, device=dev
                )
                result = self._cpu_net(ids, ext, g, p).item()
            else:
                result = self._cpu_net(ids, ext).item()

        if len(self._fwd_cache) > 5000:
            self._fwd_cache.clear()
        self._fwd_cache[h] = result
        return result

    def predict(self, source_code: str) -> int:
        if not self.trained:
            return 0
        return 1 if self._forward(source_code) > 0 else 0

    def predict_score(self, source_code: str) -> float:
        if not self.trained:
            return 0.5
        logit = self._forward(source_code)
        return float(1.0 / (1.0 + math.exp(-max(min(logit, 10), -10))))


# ─────────────────────────────────────────────────────────────────────
# Convenience: train all four models
# ─────────────────────────────────────────────────────────────────────

def create_and_train_models(vuln_type: str,
                            train_vuln: List[str],
                            train_safe: List[str]) -> Dict[str, VictimModelBase]:
    models: Dict[str, VictimModelBase] = {}
    train_codes = train_vuln + train_safe
    train_labels = [1] * len(train_vuln) + [0] * len(train_safe)
    for name in MODEL_NAMES:
        m = PyTorchVictimModel(name, vuln_type)
        ep = 50 if name == "Clear" else 30
        lr = 2e-3 if name == "Clear" else 1e-3
        acc = m.train_model(train_codes, train_labels, epochs=ep, lr=lr)
        models[name] = m
        print(f"    {name}: train acc = {acc:.1f}%")
    return models
