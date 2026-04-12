"""
Main validation pipeline orchestrator.

Loads SBOM + Trivy vulnerability reports, runs static analysis on the target
repository, applies the rule engine, calls the LLM for uncertain cases, and
writes four JSON output files:

  filtered_vulnerabilities.json  — decisions where final_label == KEEP
  removed_vulnerabilities.json   — decisions where final_label == REMOVE
  detailed_log.json              — all decisions with full audit detail
  validation_report.json         — ValidationReport summary

Can be invoked directly as a CLI script or called programmatically via
run_pipeline().
"""

import argparse
import json
from pathlib import Path
from typing import Optional

from research.llm_validation.validator import validate_with_llm
from research.models import (
    FinalDecision,
    FinalLabel,
    RuleDecision,
    ValidationReport,
    Vulnerability,
)
from research.pipeline.decision_engine import make_decision
from research.rule_engine.rules import apply_rules
from research.static_analysis.parser import parse_repository
from research.static_analysis.signals import (
    build_basic_call_graph,
    compute_static_signals,
    detect_input_sources,
    detect_sanitization,
)
from research.utils.logger import get_logger

logger = get_logger(__name__)


# ── Input loaders ─────────────────────────────────────────────────────────────

def load_trivy_vulnerabilities(trivy_path: str) -> list[Vulnerability]:
    """
    Load and normalize vulnerabilities from a Trivy JSON report.

    Trivy output structure:
        {"Results": [{"Vulnerabilities": [...]}]}

    Each inner vulnerability has: VulnerabilityID, PkgName, InstalledVersion,
    Severity, Description. The affected_functions list is always empty here
    since Trivy does not provide function-level data.

    Deduplication is applied using a composite key of (id, package).

    Args:
        trivy_path: Path to the Trivy JSON output file.

    Returns:
        Deduplicated list of Vulnerability objects.
    """
    with open(trivy_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    seen: dict[str, Vulnerability] = {}

    for result in data.get("Results", []):
        # Trivy sometimes sets Vulnerabilities to null — guard against it
        vulns = result.get("Vulnerabilities") or []
        for v in vulns:
            vuln_id = v.get("VulnerabilityID", "")
            pkg_name = v.get("PkgName", "")
            if not vuln_id or not pkg_name:
                continue

            key = f"{vuln_id}::{pkg_name}"
            if key not in seen:
                seen[key] = Vulnerability(
                    id=vuln_id,
                    package=pkg_name,
                    version=v.get("InstalledVersion", ""),
                    severity=v.get("Severity", "UNKNOWN"),
                    description=v.get("Description", ""),
                    affected_functions=[],
                )

    logger.info(
        "Loaded Trivy vulnerabilities",
        extra={"count": len(seen), "path": trivy_path},
    )
    return list(seen.values())


def load_sbom(sbom_path: str) -> dict:
    """
    Load the raw Syft SBOM JSON as a Python dict.

    Used for audit logging only in this pipeline; SBOM component correlation
    is handled by the existing ai_engine/nodes/sbom_node.py.

    Args:
        sbom_path: Path to the Syft SBOM JSON file.

    Returns:
        Raw parsed dict from the SBOM file.
    """
    with open(sbom_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    component_count = len(data.get("artifacts", data.get("components", [])))
    logger.info(
        "Loaded SBOM",
        extra={"path": sbom_path, "component_count": component_count},
    )
    return data


# ── Output writers ────────────────────────────────────────────────────────────

def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    logger.info("Written output file", extra={"path": str(path)})


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    sbom_path: str,
    trivy_path: str,
    repo_path: str,
    output_dir: str,
    threshold: float = 0.75,
    disable_llm: bool = False,
) -> ValidationReport:
    """
    Execute the full SBOM vulnerability validation pipeline.

    Args:
        sbom_path:    Path to Syft SBOM JSON file.
        trivy_path:   Path to Trivy vulnerability JSON file.
        repo_path:    Filesystem path to the target repository.
        output_dir:   Directory to write output JSON files into.
        threshold:    LLM confidence threshold for REMOVE decisions (0.0–1.0).
        disable_llm:  If True, skip LLM calls entirely (useful for testing).

    Returns:
        ValidationReport summarizing all decisions made.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Load inputs ───────────────────────────────────────────────────
    vulnerabilities = load_trivy_vulnerabilities(trivy_path)
    _sbom = load_sbom(sbom_path)  # loaded for audit; not used further here

    # ── Step 2: Parse repository (done once, reused for all vulns) ────────────
    logger.info("Parsing repository", extra={"repo_path": repo_path})
    file_asts = parse_repository(repo_path)

    # ── Step 3: Pre-compute expensive global signals once ────────────────────
    call_graph = build_basic_call_graph(file_asts)
    global_input_controlled = detect_input_sources(file_asts)
    global_sanitized = detect_sanitization(file_asts)

    logger.info(
        "Global signals computed",
        extra={
            "input_controlled": global_input_controlled,
            "sanitized": global_sanitized,
            "call_graph_size": len(call_graph),
        },
    )

    # ── Step 4: Per-vulnerability analysis ────────────────────────────────────
    decisions: list[FinalDecision] = []
    errors: list[str] = []

    for vulnerability in vulnerabilities:
        try:
            # Static analysis — use pre-computed global overrides
            signals = compute_static_signals(
                vulnerability=vulnerability,
                file_asts=file_asts,
                call_graph=call_graph,
                input_controlled_override=global_input_controlled,
                sanitized_override=global_sanitized,
            )

            # Rule engine
            rule_result = apply_rules(signals)

            # LLM validation (only for UNCERTAIN cases)
            llm_result: Optional[object] = None
            if rule_result.decision == RuleDecision.UNCERTAIN and not disable_llm:
                llm_result = validate_with_llm(vulnerability, signals)

            # Final decision
            decision = make_decision(vulnerability, rule_result, llm_result, threshold)
            decisions.append(decision)

            logger.info(
                "Vulnerability processed",
                extra={
                    "vulnerability_id": vulnerability.id,
                    "final_label": decision.final_label,
                    "method": decision.method,
                },
            )

        except Exception as e:
            error_msg = f"Error processing {vulnerability.id}: {e}"
            logger.error("Vulnerability processing failed", extra={"error": error_msg})
            errors.append(error_msg)

    # ── Step 5: Build report ──────────────────────────────────────────────────
    kept = [d for d in decisions if d.final_label == FinalLabel.KEEP]
    removed = [d for d in decisions if d.final_label == FinalLabel.REMOVE]

    report = ValidationReport(
        total_input=len(vulnerabilities),
        kept_count=len(kept),
        removed_count=len(removed),
        decisions=decisions,
        errors=errors,
    )

    # ── Step 6: Write output files ────────────────────────────────────────────
    _write_json(
        output_path / "filtered_vulnerabilities.json",
        [d.model_dump(mode="json") for d in kept],
    )
    _write_json(
        output_path / "removed_vulnerabilities.json",
        [d.model_dump(mode="json") for d in removed],
    )
    _write_json(
        output_path / "detailed_log.json",
        [d.model_dump(mode="json") for d in decisions],
    )
    _write_json(
        output_path / "validation_report.json",
        report.model_dump(mode="json"),
    )

    logger.info(
        "Pipeline complete",
        extra={
            "total": len(vulnerabilities),
            "kept": len(kept),
            "removed": len(removed),
            "errors": len(errors),
        },
    )
    return report


# ── CLI entry point ───────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SBOM Vulnerability Validation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            "  python run_validation.py \\\n"
            "    --sbom scan-results/sbom.json \\\n"
            "    --trivy scan-results/trivy.json \\\n"
            "    --repo ./targetrepo \\\n"
            "    --output-dir research_outputs"
        ),
    )
    parser.add_argument("--sbom", required=True, help="Path to Syft SBOM JSON file")
    parser.add_argument("--trivy", required=True, help="Path to Trivy vulnerability JSON file")
    parser.add_argument("--repo", required=True, help="Path to target repository directory")
    parser.add_argument(
        "--output-dir",
        default="research_outputs",
        help="Output directory for JSON reports (default: research_outputs)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.75,
        help="LLM confidence threshold for REMOVE decisions (default: 0.75)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM calls — rule-based decisions only",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    result = run_pipeline(
        sbom_path=args.sbom,
        trivy_path=args.trivy,
        repo_path=args.repo,
        output_dir=args.output_dir,
        threshold=args.threshold,
        disable_llm=args.no_llm,
    )
    print(f"\nPipeline complete:")
    print(f"  Total input:  {result.total_input}")
    print(f"  Kept:         {result.kept_count}")
    print(f"  Removed:      {result.removed_count}")
    if result.errors:
        print(f"  Errors:       {len(result.errors)}")
