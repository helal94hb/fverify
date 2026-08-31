"""Embedding match math: cosine similarity against a threshold.

The verdict is computed here, server-side, never on the device.
"""

import math
from typing import Literal

Verdict = Literal["verified", "rejected"]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity in [-1, 1]. Zero-norm or mismatched vectors score 0.0."""
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def verdict_for(score: float, threshold: float) -> Verdict:
    return "verified" if score >= threshold else "rejected"
