"""
PyTorch architectures for the four victim models.

  AMEDetector    — TextCNN + GraphFNN + PatternFNN + attention fusion
  ConvMHSADetector — MHSA → Conv1D(2,3,4) → GlobalMaxPool → Dense
  GCNProxyDetector — GCN proxy with adjacency-aware message passing
  ClearDetector  — Contrastive Learning + Transformer Encoder
"""

import math

import torch
import torch.nn as nn
import torch.nn.functional as F

MAX_INPUT_LEN = 512


# ─────────────────────────────────────────────────────────────────────
# AME  (AMEVulDetector — ISSRE 2021)
# ─────────────────────────────────────────────────────────────────────

class AMEDetector(nn.Module):
    """TextCNN + GraphFNN + PatternFNN + attention fusion."""

    def __init__(self, vocab_size, embed_dim=128, extra_dim=57,
                 graph_dim=32, pattern_dim=3):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        nf = 64
        self.convs = nn.ModuleList(
            [nn.Conv1d(embed_dim, nf, k) for k in (2, 3, 4, 5)]
        )
        tcnn_out = nf * 4
        # Graph feature FNN
        self.g_fc1 = nn.Linear(graph_dim, 64)
        self.g_fc2 = nn.Linear(64, 64)
        # Pattern feature FNN
        self.p_fc1 = nn.Linear(pattern_dim, 32)
        self.p_fc2 = nn.Linear(32, 32)
        # Attention-based fusion
        fused = tcnn_out + 64 + 32 + extra_dim
        self.attn_fc = nn.Linear(fused, fused)
        self.fc1 = nn.Linear(fused, 128)
        self.fc2 = nn.Linear(128, 1)
        self.drop = nn.Dropout(0.3)

    def forward(self, token_ids, extra, graph_feat, pattern_feat):
        x = self.embedding(token_ids).permute(0, 2, 1)
        t = torch.cat(
            [F.relu(c(x)).max(dim=2).values for c in self.convs], dim=1
        )
        g = F.relu(self.g_fc2(F.relu(self.g_fc1(graph_feat))))
        p = F.relu(self.p_fc2(F.relu(self.p_fc1(pattern_feat))))
        fused = torch.cat([t, g, p, extra], dim=1)
        attn_w = torch.sigmoid(self.attn_fc(fused))
        fused = fused * attn_w
        return self.fc2(self.drop(F.relu(self.fc1(fused)))).squeeze(-1)


# ─────────────────────────────────────────────────────────────────────
# ConvMHSA  (ISSRE 2023)
# ─────────────────────────────────────────────────────────────────────

class ConvMHSADetector(nn.Module):
    """MHSA → Conv1D(2,3,4) → GlobalMaxPool → Dense(200)."""

    def __init__(self, vocab_size, embed_dim=128, n_heads=4, extra_dim=57):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.q = nn.Linear(embed_dim, embed_dim, bias=False)
        self.k = nn.Linear(embed_dim, embed_dim, bias=False)
        self.v = nn.Linear(embed_dim, embed_dim, bias=False)
        self.combine = nn.Linear(embed_dim, embed_dim, bias=False)
        self.n_heads = n_heads
        self.head_dim = embed_dim // n_heads
        self.conv2 = nn.Conv1d(embed_dim, 2, 2)
        self.conv3 = nn.Conv1d(embed_dim, 2, 3)
        self.conv4 = nn.Conv1d(embed_dim, 2, 4)
        self.fc1 = nn.Linear(6 + extra_dim, 200)
        self.fc2 = nn.Linear(200, 1)
        self.drop = nn.Dropout(0.1)

    def forward(self, token_ids, extra):
        B, L = token_ids.shape
        D = self.embedding.embedding_dim
        x = self.embedding(token_ids)
        q = self.q(x).view(B, L, self.n_heads, self.head_dim).permute(0, 2, 1, 3)
        k = self.k(x).view(B, L, self.n_heads, self.head_dim).permute(0, 2, 1, 3)
        v = self.v(x).view(B, L, self.n_heads, self.head_dim).permute(0, 2, 1, 3)
        sc = torch.matmul(q, k.transpose(-2, -1)) / math.sqrt(self.head_dim)
        attn = torch.matmul(F.softmax(sc, dim=-1), v)
        x = self.combine(attn.permute(0, 2, 1, 3).contiguous().view(B, L, D))
        x = x.permute(0, 2, 1)
        c2 = F.relu(self.conv2(x)).max(dim=2).values
        c3 = F.relu(self.conv3(x)).max(dim=2).values
        c4 = F.relu(self.conv4(x)).max(dim=2).values
        x = torch.cat([c2, c3, c4, extra], dim=1)
        return self.fc2(self.drop(F.relu(self.fc1(x)))).squeeze(-1)


# ─────────────────────────────────────────────────────────────────────
# GPSCVul  (GCN proxy)
# ─────────────────────────────────────────────────────────────────────

class GCNProxyDetector(nn.Module):
    """GCN proxy with adjacency-aware message passing + expert patterns."""

    def __init__(self, vocab_size, embed_dim=128, extra_dim=57,
                 graph_dim=32, pattern_dim=3):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.mp1_msg = nn.Linear(embed_dim, 64)
        self.mp1_upd = nn.Linear(64 + embed_dim, 64)
        self.mp2_msg = nn.Linear(64, 64)
        self.mp2_upd = nn.Linear(64 + 64, 64)
        self.g_fc1 = nn.Linear(graph_dim, 64)
        self.g_fc2 = nn.Linear(64, 64)
        self.p_fc1 = nn.Linear(pattern_dim, 32)
        self.p_fc2 = nn.Linear(32, 32)
        fused = 64 + 64 + 32 + extra_dim
        self.fc1 = nn.Linear(fused, 64)
        self.fc2 = nn.Linear(64, 1)
        self.drop = nn.Dropout(0.3)

    def _message_pass(self, x, msg_fn, upd_fn):
        B, L, D = x.shape
        msg = msg_fn(x)
        padded = F.pad(msg.permute(0, 2, 1), (2, 2), mode='constant', value=0)
        agg = F.avg_pool1d(padded, kernel_size=5, stride=1, padding=0).permute(0, 2, 1)
        return F.relu(upd_fn(torch.cat([agg, x], dim=-1)))

    def forward(self, token_ids, extra, graph_feat, pattern_feat):
        mask = (token_ids != 0).unsqueeze(-1).float()
        x = self.embedding(token_ids)
        x = self._message_pass(x, self.mp1_msg, self.mp1_upd)
        x = self._message_pass(x, self.mp2_msg, self.mp2_upd)
        lengths = mask.sum(dim=1).clamp(min=1)
        x = (x * mask).sum(dim=1) / lengths
        g = F.relu(self.g_fc2(F.relu(self.g_fc1(graph_feat))))
        p = F.relu(self.p_fc2(F.relu(self.p_fc1(pattern_feat))))
        fused = torch.cat([x, g, p, extra], dim=1)
        return self.fc2(self.drop(F.relu(self.fc1(fused)))).squeeze(-1)


# ─────────────────────────────────────────────────────────────────────
# Clear  (ICSE 2024)
# ─────────────────────────────────────────────────────────────────────

class ClearDetector(nn.Module):
    """Contrastive Learning + Transformer Encoder + classifier."""

    def __init__(self, vocab_size, embed_dim=128, n_heads=4, n_layers=2,
                 extra_dim=57):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_emb = nn.Embedding(MAX_INPUT_LEN, embed_dim)
        enc_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=n_heads,
            dim_feedforward=embed_dim * 4, dropout=0.1, batch_first=True,
        )
        self.transformer = nn.TransformerEncoder(enc_layer, num_layers=n_layers)
        self.proj1 = nn.Linear(embed_dim, embed_dim, bias=False)
        self.proj2 = nn.Linear(embed_dim, embed_dim, bias=False)
        self.ln = nn.LayerNorm(embed_dim)
        self.fc = nn.Linear(embed_dim * 2 + extra_dim, 1)
        self.drop = nn.Dropout(0.1)

    def encode(self, token_ids):
        B, L = token_ids.shape
        mask = (token_ids == 0)
        x = self.embedding(token_ids) + self.pos_emb(
            torch.arange(L, device=token_ids.device)
        )
        x = self.transformer(x, src_key_padding_mask=mask)
        lengths = (~mask).sum(dim=1, keepdim=True).float().clamp(min=1)
        return (x * (~mask).unsqueeze(-1).float()).sum(dim=1) / lengths

    def forward(self, token_ids, extra):
        enc = self.encode(token_ids)
        p1 = self.ln(self.proj1(enc))
        p2 = self.ln(self.proj2(enc))
        x = torch.cat([p1, p2, extra], dim=1)
        return self.fc(self.drop(x)).squeeze(-1)

    def contrastive_loss(self, ids1, ids2, labels, temperature=0.07):
        """CLIP-style contrastive loss for pre-training."""
        e1 = F.normalize(self.proj1(self.encode(ids1)), dim=-1)
        e2 = F.normalize(self.proj1(self.encode(ids2)), dim=-1)
        sim = torch.matmul(e1, e2.T) / temperature
        B = sim.shape[0]
        pos_mask = (labels.unsqueeze(0) == labels.unsqueeze(1)).float()
        pos_mask.fill_diagonal_(0)
        neg_mask = 1.0 - pos_mask
        neg_mask.fill_diagonal_(0)
        exp_sim = torch.exp(sim)
        pos_sum = (exp_sim * pos_mask).sum(dim=1)
        neg_sum = (exp_sim * neg_mask).sum(dim=1)
        loss = -torch.log(pos_sum / (pos_sum + neg_sum + 1e-8) + 1e-8)
        return (loss[pos_sum > 0].mean()
                if (pos_sum > 0).any()
                else torch.tensor(0.0, device=sim.device))
