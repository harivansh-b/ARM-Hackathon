"""Operating-point selection for a safety-oriented detector."""

from __future__ import annotations


def select_threshold(labels: list[int], scores: list[float], max_false_positive_rate: float = 0.001, min_recall: float = 0.8) -> dict[str, float | int]:
    if len(labels) != len(scores) or not labels:
        raise ValueError("labels and scores must have equal non-zero length")
    candidates = sorted(set([0.0, 1.0, *scores]))
    valid: list[tuple[float, float, float]] = []
    for threshold in candidates:
        predicted = [score >= threshold for score in scores]
        tp = sum(label == 1 and prediction for label, prediction in zip(labels, predicted))
        tn = sum(label == 0 and not prediction for label, prediction in zip(labels, predicted))
        fp = sum(label == 0 and prediction for label, prediction in zip(labels, predicted))
        fn = sum(label == 1 and not prediction for label, prediction in zip(labels, predicted))
        fpr = fp / (fp + tn) if fp + tn else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        precision = tp / (tp + fp) if tp + fp else 0.0
        if fpr <= max_false_positive_rate and recall >= min_recall:
            valid.append((threshold, recall, precision))
    if not valid:
        raise ValueError("no threshold satisfies the requested false-positive and recall constraints")
    threshold, recall, precision = max(valid, key=lambda row: (row[2], row[1], row[0]))
    return {"threshold": threshold, "calibration_recall": recall, "calibration_precision": precision, "max_false_positive_rate": max_false_positive_rate, "min_recall": min_recall, "candidate_count": len(candidates)}
