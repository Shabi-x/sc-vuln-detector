"""Solidity tokenizer with vocabulary building for neural models."""

import re
from typing import Dict, List
from collections import Counter

import torch


class SolidityTokenizer:
    """Word-level tokenizer that builds a fixed vocabulary from a corpus."""

    SPECIAL = ["<PAD>", "<UNK>"]

    def __init__(self, max_vocab: int = 3000, max_len: int = 512):
        self.max_vocab = max_vocab
        self.max_len = max_len
        self.word2idx: Dict[str, int] = {}
        self.idx2word: Dict[int, str] = {}
        self.vocab_size = 0

    @staticmethod
    def _tokenize(code: str) -> List[str]:
        return re.findall(
            r'[a-zA-Z_]\w*|[{}()\[\];,.]|[+\-*/=<>!&|^~%]+|\d+', code
        )

    def build_vocab(self, codes: List[str]):
        counter: Counter = Counter()
        for c in codes:
            counter.update(self._tokenize(c))
        most_common = counter.most_common(self.max_vocab - len(self.SPECIAL))
        self.word2idx = {w: i for i, w in enumerate(self.SPECIAL)}
        for w, _ in most_common:
            self.word2idx[w] = len(self.word2idx)
        self.idx2word = {i: w for w, i in self.word2idx.items()}
        self.vocab_size = len(self.word2idx)

    def encode(self, code: str) -> List[int]:
        tokens = self._tokenize(code)[:self.max_len]
        unk = self.word2idx["<UNK>"]
        ids = [self.word2idx.get(t, unk) for t in tokens]
        ids += [0] * (self.max_len - len(ids))
        return ids

    def encode_batch(self, codes: List[str]) -> torch.Tensor:
        return torch.tensor([self.encode(c) for c in codes], dtype=torch.long)
