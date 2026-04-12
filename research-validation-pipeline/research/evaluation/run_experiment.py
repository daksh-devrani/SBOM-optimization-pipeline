def evaluate(ground_truth: list[dict], decisions: list[FinalDecision]) -> dict:
    ground_truth_dict = {item['vulnerability_id']: item['label'] for item in ground_truth}
    
    tp = fp = fn = tn = 0

    for decision in decisions:
        if decision.final_label == FinalLabel.KEEP:
            if ground_truth_dict.get(decision.vulnerability_id) == "TP":
                tp += 1
            elif ground_truth_dict.get(decision.vulnerability_id) == "FP":
                fp += 1
        elif decision.final_label == FinalLabel.REMOVE:
            if ground_truth_dict.get(decision.vulnerability_id) == "TP":
                fn += 1
            elif ground_truth_dict.get(decision.vulnerability_id) == "FP":
                tn += 1

    fpr = compute_fpr(fp, tn)
    precision = compute_precision(tp, fp)
    recall = compute_recall(tp, fn)
    f1 = compute_f1(precision, recall)
    accuracy = compute_accuracy(tp, tn, fp, fn)

    baseline_fpr = fp / (fp + tn) if (fp + tn) > 0 else 1.0
    reduction_in_fpr = baseline_fpr - fpr

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "fpr": fpr,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "baseline_fpr": baseline_fpr,
        "reduction_in_fpr": reduction_in_fpr
    }