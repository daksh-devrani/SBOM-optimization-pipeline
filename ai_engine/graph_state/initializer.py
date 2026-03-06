"""
State initializer.

Loads all scanner output files and the Dockerfile,
parses them using the parsers layer, and assembles
the initial PipelineState that gets passed into the graph.

This is the bridge between the CI pipeline's file artifacts
and the AI engine's data model.
"""

import logging
from pathlib import Path

from parsers import (
    parse_semgrep,
    parse_trivy,
    parse_snyk,
    parse_sonarqube,
    parse_syft,
)
from schemas.pipeline_state import PipelineState
from schemas.vulnerability  import Vulnerability

logger = logging.getLogger(__name__)


def build_initial_state(
    semgrep_path:    str | None = None,
    trivy_path:      str | None = None,
    snyk_path:       str | None = None,
    sonarqube_path:  str | None = None,
    syft_path:       str | None = None,
    dockerfile_path: str | None = None,
    target_repo:     str | None = None,
) -> PipelineState:
    """
    Parse all scanner outputs and assemble initial PipelineState.

    Any path that is None or points to a missing file is skipped
    gracefully — the pipeline runs with whatever data is available.

    Args:
        semgrep_path:    Path to semgrep --json output file.
        trivy_path:      Path to trivy image --format json output.
        snyk_path:       Path to snyk test --json output.
        sonarqube_path:  Path to saved SonarQube API response JSON.
        syft_path:       Path to syft -o cyclonedx-json output.
        dockerfile_path: Path to the target repo's Dockerfile.
        target_repo:     Repository name string e.g. 'org/repo'.

    Returns:
        Populated PipelineState ready for graph execution.
    """

    all_vulnerabilities: list[Vulnerability] = []
    errors: list[str] = []

    # ── Parse each scanner output ─────────────────────────────────────────────
    parsers = [
        ("Semgrep",    semgrep_path,   parse_semgrep),
        ("Trivy",      trivy_path,     parse_trivy),
        ("Snyk",       snyk_path,      parse_snyk),
        ("SonarQube",  sonarqube_path, parse_sonarqube),
    ]

    for name, path, parser_fn in parsers:
        if not path:
            logger.info(f"{name}: no path provided, skipping.")
            continue
        try:
            findings = parser_fn(path)
            all_vulnerabilities.extend(findings)
            logger.info(f"{name}: loaded {len(findings)} findings.")
        except Exception as e:
            error_msg = f"{name} parser failed: {e}"
            logger.error(error_msg)
            errors.append(error_msg)

    logger.info(
        f"Total vulnerabilities loaded across all scanners: "
        f"{len(all_vulnerabilities)}"
    )

    # ── Parse SBOM ────────────────────────────────────────────────────────────
    sbom = None
    if syft_path:
        try:
            sbom = parse_syft(syft_path)
            if sbom:
                logger.info(
                    f"Syft SBOM loaded: {sbom.total_components} components."
                )
        except Exception as e:
            error_msg = f"Syft parser failed: {e}"
            logger.error(error_msg)
            errors.append(error_msg)
    else:
        logger.info("Syft: no path provided, skipping.")

    # ── Load Dockerfile ───────────────────────────────────────────────────────
    dockerfile_content = None
    if dockerfile_path:
        df_path = Path(dockerfile_path)
        if df_path.exists():
            try:
                dockerfile_content = df_path.read_text(encoding="utf-8")
                logger.info(f"Dockerfile loaded from {dockerfile_path}.")
            except Exception as e:
                error_msg = f"Failed to read Dockerfile: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        else:
            logger.warning(f"Dockerfile not found at {dockerfile_path}.")

    # ── Assemble state ────────────────────────────────────────────────────────
    return PipelineState(
        vulnerabilities=all_vulnerabilities,
        sbom=sbom,
        dockerfile_content=dockerfile_content,
        target_repo=target_repo,
        errors=errors,
    )