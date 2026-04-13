"""
Pure metric computation functions for vulnerability validation evaluation.

All functions are stateless, side-effect free, and zero-division safe.
Inputs are integer confusion matrix counts; outputs are floats.
"""


def compute_fpr(fp: int, tn: int) -> float:
    """
    False Positive Rate = FP / (FP + TN).

    Measures the fraction of true negatives (real false positives)
    that were incorrectly kept by the pipeline.

    Returns 0.0 when denominator is zero (no negatives in dataset).
    """
    denom = fp + tn
    return fp / denom if denom > 0 else 0.0


def compute_precision(tp: int, fp: int) -> float:
    """
    Precision = TP / (TP + FP).

    Of all vulnerabilities the pipeline kept, what fraction were real?

    Returns 0.0 when denominator is zero (nothing was kept).
    """
    denom = tp + fp
    return tp / denom if denom > 0 else 0.0


def compute_recall(tp: int, fn: int) -> float:
    """
    Recall (Sensitivity) = TP / (TP + FN).

    Of all real vulnerabilities, what fraction did the pipeline keep?

    Returns 0.0 when denominator is zero (no positive cases in dataset).
    """
    denom = tp + fn
    return tp / denom if denom > 0 else 0.0


def compute_f1(precision: float, recall: float) -> float:
    """
    F1 Score = 2 * (Precision * Recall) / (Precision + Recall).

    Harmonic mean of precision and recall. Penalizes extreme values.

    Returns 0.0 when both precision and recall are zero.
    """
    denom = precision + recall
    return 2 * (precision * recall) / denom if denom > 0 else 0.0


def compute_accuracy(tp: int, tn: int, fp: int, fn: int) -> float:
    """
    Accuracy = (TP + TN) / (TP + TN + FP + FN).

    Overall fraction of correct decisions.

    Returns 0.0 when no samples exist.
    """
    denom = tp + tn + fp + fn
    return (tp + tn) / denom if denom > 0 else 0.0
