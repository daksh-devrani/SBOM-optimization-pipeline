def compute_fpr(fp: int, tn: int) -> float:
    """False Positive Rate = FP / (FP + TN). Returns 0.0 if denominator is 0."""
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0

def compute_precision(tp: int, fp: int) -> float:
    """Precision = TP / (TP + FP). Returns 0.0 if denominator is 0."""
    return tp / (tp + fp) if (tp + fp) > 0 else 0.0

def compute_recall(tp: int, fn: int) -> float:
    """Recall = TP / (TP + FN). Returns 0.0 if denominator is 0."""
    return tp / (tp + fn) if (tp + fn) > 0 else 0.0

def compute_f1(precision: float, recall: float) -> float:
    """F1 = 2 * (P * R) / (P + R). Returns 0.0 if denominator is 0."""
    return 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

def compute_accuracy(tp: int, tn: int, fp: int, fn: int) -> float:
    """Accuracy = (TP + TN) / (TP + TN + FP + FN)."""
    return (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0