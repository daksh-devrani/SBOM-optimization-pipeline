"""
AI Engine entrypoint.

Called by GitHub Actions after all security scans complete.
Reads scanner output paths from environment variables,
runs the LangGraph pipeline, and writes output reports
to the outputs directory.

Usage:
    python main.py

Environment variables (all optional — pipeline skips missing ones):
    SEMGREP_REPORT      Path to semgrep JSON report
    TRIVY_REPORT        Path to trivy JSON report
    SNYK_REPORT         Path to snyk JSON report
    SONARQUBE_REPORT    Path to sonarqube JSON report
    SYFT_SBOM           Path to syft CycloneDX JSON SBOM
    DOCKERFILE_PATH     Path to target repo Dockerfile
    TARGET_REPO         Repository name e.g. 'org/repo'
    OUTPUT_DIR          Directory to write reports into (default: ./outputs)
    LLM_PROVIDER        'groq' or 'ollama' (default: groq)
    GROQ_API_KEY        Groq API key (required if LLM_PROVIDER=groq)
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from graph_state  import build_initial_state
from workflow     import build_graph
from schemas.pipeline_state import PipelineState

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# ── Output helpers ────────────────────────────────────────────────────────────

def _ensure_output_dir(output_dir: str) -> Path:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_report(output_dir: Path, filename: str, content: str) -> Path:
    """Write a text/markdown report file."""
    filepath = output_dir / filename
    filepath.write_text(content, encoding="utf-8")
    logger.info(f"Written: {filepath}")
    return filepath


def _write_json(output_dir: Path, filename: str, data: dict | list) -> Path:
    """Write a JSON file."""
    filepath = output_dir / filename
    filepath.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8"
    )
    logger.info(f"Written: {filepath}")
    return filepath


def _fixes_to_dict(state: PipelineState) -> list[dict]:
    """Serialize FixSuggestion objects to plain dicts for JSON output."""
    return [
        {
            "vulnerability_id":  f.vulnerability_id,
            "package_name":      f.package_name,
            "current_version":   f.current_version,
            "suggested_version": f.suggested_version,
            "fix_type":          f.fix_type,
            "description":       f.description,
            "safe_to_automate":  f.safe_to_automate,
        }
        for f in state.fixes
    ]


def _build_pipeline_metadata(state: PipelineState) -> dict:
    """Build a metadata summary of the pipeline run."""
    severity_counts: dict[str, int] = {}
    for v in state.vulnerabilities:
        sev = str(v.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "run_timestamp":         datetime.now(timezone.utc).isoformat(),
        "target_repo":           state.target_repo or "unknown",
        "total_vulnerabilities": len(state.vulnerabilities),
        "severity_breakdown":    severity_counts,
        "total_fixes":           len(state.fixes),
        "automatable_fixes":     sum(1 for f in state.fixes if f.safe_to_automate),
        "manual_fixes":          sum(1 for f in state.fixes if not f.safe_to_automate),
        "sbom_components":       state.sbom.total_components if state.sbom else 0,
        "pipeline_errors":       state.errors,
        "fix_log":               state.fix_log,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 60)
    logger.info("AI Security Engine starting")
    logger.info("=" * 60)

    # ── Read config from environment ──────────────────────────────────────────
    semgrep_path     = os.getenv("SEMGREP_REPORT")
    trivy_path       = os.getenv("TRIVY_REPORT")
    snyk_path        = os.getenv("SNYK_REPORT")
    sonarqube_path   = os.getenv("SONARQUBE_REPORT")
    syft_path        = os.getenv("SYFT_SBOM")
    dockerfile_path  = os.getenv("DOCKERFILE_PATH")
    target_repo      = os.getenv("TARGET_REPO")
    # Filesystem path to the cloned target repo — used by validation_node
    target_repo_path = os.getenv("TARGET_REPO_PATH")
    output_dir_str   = os.getenv("OUTPUT_DIR", "./outputs")

    logger.info(f"Target repo:  {target_repo or 'not set'}")
    logger.info(f"Output dir:   {output_dir_str}")
    logger.info(f"LLM provider: {os.getenv('LLM_PROVIDER', 'groq')}")

    # Log which scanner reports are present
    report_paths = {
        "Semgrep":    semgrep_path,
        "Trivy":      trivy_path,
        "Snyk":       snyk_path,
        "SonarQube":  sonarqube_path,
        "Syft":       syft_path,
        "Dockerfile": dockerfile_path,
        "Repo path":  target_repo_path,
    }
    for name, path in report_paths.items():
        status = f"✅ {path}" if path else "⚠️  not provided"
        logger.info(f"  {name}: {status}")

    # ── Step 1: Build initial state from scanner outputs ──────────────────────
    logger.info("\nStep 1: Parsing scanner outputs...")
    try:
        initial_state = build_initial_state(
            semgrep_path=semgrep_path,
            trivy_path=trivy_path,
            snyk_path=snyk_path,
            sonarqube_path=sonarqube_path,
            syft_path=syft_path,
            dockerfile_path=dockerfile_path,
            target_repo=target_repo,
            repo_path=target_repo_path,
        )
    except Exception as e:
        logger.critical(f"State initialization failed: {e}")
        sys.exit(1)

    logger.info(
        f"State initialized: "
        f"{len(initial_state.vulnerabilities)} vulnerabilities, "
        f"{initial_state.sbom.total_components if initial_state.sbom else 0} "
        f"SBOM components."
    )

    # ── Step 2: Build and run the graph ───────────────────────────────────────
    logger.info("\nStep 2: Building LangGraph pipeline...")
    try:
        app = build_graph()
    except Exception as e:
        logger.critical(f"Graph build failed: {e}")
        sys.exit(1)

    logger.info("Step 3: Running AI agents...")
    logger.info("  → fix_node")
    logger.info("  → summary_node")
    logger.info("  → sbom_node")

    try:
        # LangGraph expects a dict, not a Pydantic model
        final_state_dict = app.invoke(initial_state.model_dump())
        final_state = PipelineState(**final_state_dict)
    except Exception as e:
        logger.critical(f"Graph execution failed: {e}")
        sys.exit(1)

    logger.info("All agents completed successfully.")

    # ── Step 3: Write outputs ─────────────────────────────────────────────────
    logger.info("\nStep 4: Writing output reports...")
    output_dir = _ensure_output_dir(output_dir_str)

    # Security summary report
    if final_state.summary_report:
        _write_report(output_dir, "security-summary.md", final_state.summary_report)

    # SBOM optimization report
    if final_state.sbom_optimization_report:
        _write_report(
            output_dir,
            "sbom-optimization.md",
            final_state.sbom_optimization_report,
        )

    # Fix suggestions as JSON (structured, machine-readable)
    if final_state.fixes:
        _write_json(
            output_dir,
            "fix-suggestions.json",
            _fixes_to_dict(final_state),
        )

    # Pipeline metadata / audit log
    metadata = _build_pipeline_metadata(final_state)
    _write_json(output_dir, "pipeline-metadata.json", metadata)

    # Validation report (from validation_node — may be None if paths were missing)
    if final_state.validation_report:
        _write_json(output_dir, "validation-report.json", final_state.validation_report)

    # ── Step 4: Print summary to CI logs ─────────────────────────────────────
    logger.info("\n" + "=" * 60)
    logger.info("PIPELINE COMPLETE")
    logger.info("=" * 60)
    logger.info(f"  Vulnerabilities found:  {len(final_state.vulnerabilities)}")
    logger.info(f"  Fix suggestions:        {len(final_state.fixes)}")
    logger.info(
        f"  Automatable fixes:      "
        f"{sum(1 for f in final_state.fixes if f.safe_to_automate)}"
    )
    logger.info(
        f"  Manual review items:    "
        f"{sum(1 for f in final_state.fixes if not f.safe_to_automate)}"
    )
    logger.info(
        f"  SBOM components:        "
        f"{final_state.sbom.total_components if final_state.sbom else 0}"
    )
    logger.info(f"\nOutputs written to: {output_dir.resolve()}")
    logger.info(f"  📄 security-summary.md")
    logger.info(f"  📄 sbom-optimization.md")
    logger.info(f"  📄 fix-suggestions.json")
    logger.info(f"  📄 pipeline-metadata.json")
    if final_state.validation_report:
        logger.info(f"  📄 validation-report.json")
    if final_state.validation_errors:
        logger.warning(
            f"\n⚠️  {len(final_state.validation_errors)} validation error(s):"
        )
        for err in final_state.validation_errors:
            logger.warning(f"  - {err}")

    if final_state.errors:
        logger.warning(f"\n⚠️  {len(final_state.errors)} non-fatal error(s) during run:")
        for err in final_state.errors:
            logger.warning(f"  - {err}")


if __name__ == "__main__":
    main()