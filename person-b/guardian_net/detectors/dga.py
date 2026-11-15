"""Domain Generation Algorithm (DGA) detector.

Detects algorithmically generated domain names based on:
- Elevated character/n-gram entropy
- High consonant ratio and unnatural consonant streaks
- Digit ratios and absence of natural language vowels
- High NXDOMAIN response frequency
"""
from __future__ import annotations

import collections
import math
import re
from typing import Any

from ..dnswire import RCODE_NXDOMAIN
from ..evidence import create_evidence

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def char_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = collections.Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def consonant_vowel_metrics(s: str) -> tuple[float, int]:
    """Returns (consonant_ratio, max_consecutive_consonants)."""
    alpha = [c for c in s.lower() if c.isalpha()]
    if not alpha:
        return 0.0, 0
    cons = sum(1 for c in alpha if c in CONSONANTS)
    ratio = cons / len(alpha)

    max_streak = 0
    cur_streak = 0
    for c in alpha:
        if c in CONSONANTS:
            cur_streak += 1
            if cur_streak > max_streak:
                max_streak = cur_streak
        else:
            cur_streak = 0
    return ratio, max_streak


class DGADetector:
    """Detects DGA patterns in queried domains and tracks NXDOMAIN rates."""

    def __init__(
        self,
        entropy_threshold: float = 3.4,
        consonant_ratio_threshold: float = 0.80,
        consonant_streak_threshold: int = 5,
        nxdomain_rate_threshold: float = 0.60,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.consonant_ratio_threshold = consonant_ratio_threshold
        self.consonant_streak_threshold = consonant_streak_threshold
        self.nxdomain_rate_threshold = nxdomain_rate_threshold

        # Track query outcome stats per client or domain prefix
        self._history: collections.deque[tuple[str, int]] = collections.deque(maxlen=200)

    def analyze_domain(
        self,
        domain: str,
        rcode: int | None = None,
        timestamp: int | None = None,
    ) -> dict[str, Any] | None:
        clean = domain.strip().strip(".").lower()
        parts = clean.split(".")
        if not parts:
            return None

        # Inspect main domain label (e.g. 'xgjkqzpw' in 'xgjkqzpw.com')
        main_label = parts[-2] if len(parts) >= 2 else parts[0]
        if len(main_label) < 6:
            # Short names like 'bbc.co.uk' or 'cnn.com' have low statistical significance
            return None

        entropy = round(char_entropy(main_label), 3)
        cons_ratio, max_streak = consonant_vowel_metrics(main_label)
        digit_count = sum(1 for c in main_label if c.isdigit())

        reasons: list[str] = []
        score = 0.0

        if entropy >= self.entropy_threshold:
            reasons.append(f"Elevated domain entropy: {entropy:.2f} (threshold {self.entropy_threshold})")
            score += 0.35

        if cons_ratio >= self.consonant_ratio_threshold:
            reasons.append(f"High consonant ratio: {cons_ratio * 100:.1f}%")
            score += 0.30

        if max_streak >= self.consonant_streak_threshold:
            reasons.append(f"Unnatural consonant sequence: {max_streak} consecutive consonants")
            score += 0.20

        if digit_count >= 3:
            reasons.append(f"Embedded numeric digits in host label: {digit_count}")
            score += 0.15

        # Record and analyze NXDOMAIN history
        if rcode is not None:
            self._history.append((clean, rcode))
            if len(self._history) >= 10:
                nx_count = sum(1 for _, rc in self._history if rc == RCODE_NXDOMAIN)
                nx_ratio = nx_count / len(self._history)
                if nx_ratio >= self.nxdomain_rate_threshold:
                    reasons.append(f"High NXDOMAIN response ratio: {nx_ratio * 100:.1f}%")
                    score += 0.25

        score = min(score, 0.99)
        if score < 0.35:
            return None

        return create_evidence(
            source="DNS",
            event_type="DGA",
            entity_type="DOMAIN",
            entity_value=clean,
            score=score,
            reasons=reasons,
            timestamp=timestamp,
            metadata={
                "domain": clean,
                "label": main_label,
                "entropy": entropy,
                "consonant_ratio": round(cons_ratio, 2),
                "consonant_streak": max_streak,
            },
        )
