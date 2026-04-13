"""
Evaluation experiment runner.

Compares the validated pipeline output against ground truth labels to compute
standard classification metrics (FPR, Precision, Recall, F1, Accuracy).

Ground truth file format (JSON array):
    [
        {"vulnerability_id": "CVE-2023-1234", "label": "TP"},
        {"vulnerability_id": "CVE-2023-5678", "label": "FP"},
        ...
    ]

Valid label values:
    TP — true positive: real vulnerability that should be KEPT
    FP — false positive: not actually exploitable, should be REMOVED
    FN — false negative: real vulnerability that was REMOVED (missed)
    TN — true negative: correctly removed non-exploitable finding

The pipeline log (detailed_log.json) contains FinalDecision objects
serialized by run_validation.py.

Usage:
    python run_experiment.py \
        --ground-truth ground_truth.json \
        --pipeline-log research_outputs/detailed_log.json \
        --output experiment_results.json
"""

import argparse
import json
import logging
from pathlib import Path

from research.evaluation.metrics import (
    compute_accuracy,
    compute_f1,
    compute_fpr,
    compute_precision,
    compute_recall,
)
from research.models import FinalDecision, FinalLabel

logger = logging.getLogger(__name__)


def evaluate(
    ground_truth: list[dict],
    decisions: list[FinalDecision],
) -> dict:
    """
    Compute classification metrics by comparing pipeline decisions to ground truth.

    Confusion matrix mapping:
        pipeline=KEEP  + ground_truth=TP  → TP  (correctly kept real vuln)
        pipeline=KEEP  + ground_truth=FP  → FP  (incorrectly kept non-exploitable)
        pipeline=REMOVE + ground_truth=TP → FN  (incorrectly removed real vuln)
        pipeline=REMOVE + ground_truth=FP → TN  (correctly removed non-exploitable)

    Vulnerabilities not present in the ground truth file are skipped and counted.

    Args:
        ground_truth: List of dicts with 'vulnerability_id' and 'label' keys.
        decisions:    List of FinalDecision objects from the pipeline run.

    Returns:
        Dict with confusion matrix counts and all computed metrics.
    """
    gt_map: dict[str, str] = {
        item["vulnerability_id"]: item["label"]
        for item in ground_truth
        if "vulnerability_id" in item and "label" in item
    }

    tp = fp = fn = tn = 0
    skipped: list[str] = []

    for decision in decisions:
        label = gt_map.get(decision.vulnerability_id)

        if label is None:
            skipped.append(decision.vulnerability_id)
            continue

        is_kept = decision.final_label == FinalLabel.KEEP
        is_removed = decision.final_label == FinalLabel.REMOVE

        if is_kept and label == "TP":
            tp += 1
        elif is_kept and label == "FP":
            fp += 1
        elif is_removed and label == "TP":
            fn += 1
        elif is_removed and label == "FP":
            tn += 1

    if skipped:
        logger.warning(
            "Skipped %d vulnerabilities not found in ground truth: %s",
            len(skipped),
            skipped[:10],
        )

    # Compute metrics
    fpr = compute_fpr(fp, tn)
    precision = compute_precision(tp, fp)
    recall = compute_recall(tp, fn)
    f1 = compute_f1(precision, recall)
    accuracy = compute_accuracy(tp, tn, fp, fn)

    # Baseline FPR: assume a naive system keeps everything (no filtering)
    # → all FPs are incorrectly kept → baseline_fpr = FP / (FP + TN) = 1.0
    # when there are any negatives. More precisely: FP rate if we keep all.
    total_negatives = fp + tn
    baseline_fpr = 1.0 if total_negatives > 0 else 0.0
    reduction_in_fpr = baseline_fpr - fpr

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "metrics": {
            "fpr": round(fpr, 6),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "accuracy": round(accuracy, 6),
        },
        "baseline": {
            "baseline_fpr": round(baseline_fpr, 6),
            "reduction_in_fpr": round(reduction_in_fpr, 6),
        },
        "meta": {
            "total_evaluated": tp + fp + fn + tn,
            "skipped_count": len(skipped),
            "skipped_ids": skipped,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate SBOM validation pipeline against ground truth labels.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--ground-truth",
        required=True,
        help="Path to ground truth JSON file (array of {vulnerability_id, label} objects)",
    )
    parser.add_argument(
        "--pipeline-log",
        required=True,
        help="Path to detailed_log.json produced by run_validation.py",
    )
    parser.add_argument(
        "--output",
        default="experiment_results.json",
        help="Path to write experiment results JSON (default: experiment_results.json)",
    )
    args = parser.parse_args()

    # ── Load inputs ───────────────────────────────────────────────────────────
    with open(args.ground_truth, "r", encoding="utf-8") as f:
        ground_truth: list[dict] = json.load(f)

    with open(args.pipeline_log, "r", encoding="utf-8") as f:
        log_data: list[dict] = json.load(f)

    # Deserialize FinalDecision objects from JSON dicts
    decisions = [FinalDecision(**d) for d in log_data]

    # ── Run evaluation ────────────────────────────────────────────────────────
    results = evaluate(ground_truth, decisions)

    # ── Write results ─────────────────────────────────────────────────────────
    output_path = Path(args.output)
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    # ── Print summary to stdout ───────────────────────────────────────────────
    m = results["metrics"]
    cm = results["confusion_matrix"]
    bl = results["baseline"]
    meta = results["meta"]

    print("\n" + "=" * 50)
    print("EVALUATION RESULTS")
    print("=" * 50)
    print(f"  Total evaluated:      {meta['total_evaluated']}")
    print(f"  Skipped (no GT):      {meta['skipped_count']}")
    print()
    print(f"  Confusion matrix:")
    print(f"    TP={cm['tp']}  FP={cm['fp']}")
    print(f"    FN={cm['fn']}  TN={cm['tn']}")
    print()
    print(f"  FPR:                  {m['fpr']:.4f}")
    print(f"  Precision:            {m['precision']:.4f}")
    print(f"  Recall:               {m['recall']:.4f}")
    print(f"  F1:                   {m['f1']:.4f}")
    print(f"  Accuracy:             {m['accuracy']:.4f}")
    print()
    print(f"  Baseline FPR:         {bl['baseline_fpr']:.4f}")
    print(f"  Reduction in FPR:     {bl['reduction_in_fpr']:.4f}")
    print("=" * 50)
    print(f"\nResults written to: {output_path.resolve()}")


if __name__ == "__main__":
    main()
