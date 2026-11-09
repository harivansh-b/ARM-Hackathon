"""Metrics used by the offline evaluation report."""

from __future__ import annotations


def binary_metrics(labels: list[int], scores: list[float], threshold: float = 0.5) -> dict[str, float | int]:
    if len(labels) != len(scores) or not labels:
        raise ValueError("labels and scores must have equal non-zero length")
    predictions = [score >= threshold for score in scores]
    tp = sum(label == 1 and prediction for label, prediction in zip(labels, predictions))
    tn = sum(label == 0 and not prediction for label, prediction in zip(labels, predictions))
    fp = sum(label == 0 and prediction for label, prediction in zip(labels, predictions))
    fn = sum(label == 1 and not prediction for label, prediction in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"count": len(labels), "tp": tp, "tn": tn, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": fpr}


def pr_auc(labels: list[int], scores: list[float]) -> float:
    if len(labels) != len(scores) or not labels:
        raise ValueError("labels and scores must have equal non-zero length")
    positives = sum(labels)
    if not positives:
        return 0.0
    order = sorted(range(len(scores)), key=lambda index: scores[index], reverse=True)
    seen_positive = 0
    area = 0.0
    previous_recall = 0.0
    for rank, index in enumerate(order, 1):
        if labels[index] == 1:
            seen_positive += 1
            recall = seen_positive / positives
            precision = seen_positive / rank
            area += (recall - previous_recall) * precision
            previous_recall = recall
    return area
