"""
SBOM Optimization Agent Node.

Responsibilities:
- Analyze the software bill of materials for the scanned container image
- Identify unused/redundant dependencies
- Flag risky or outdated packages
- Detect unpinned versions
- Cross-reference SBOM components with known vulnerabilities
- Produce an actionable SBOM optimization report in markdown

LangGraph contract:
- Input:  PipelineState (reads: sbom, vulnerabilities, target_repo)
- Output: dict with key 'sbom_optimization_report' to merge into state

Note on Syft's role:
  Syft generates the SBOM — it does NOT find vulnerabilities.
  This agent correlates the SBOM with vuln data from other scanners
  to show which components are both present AND vulnerable.
"""

import logging
from collections import defaultdict
from langchain_core.messages import SystemMessage, HumanMessage

from config.llm import get_llm
from schemas.pipeline_state import PipelineState
from schemas.sbom import SBOM, SBOMComponent
from schemas.vulnerability import Vulnerability, Severity

logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────

# Packages that are build/dev tools and should not be in final images
# These are strong candidates for multi-stage build moves
KNOWN_DEV_PACKAGES = {
    # Build tools
    "gcc", "g++", "make", "cmake", "build-essential", "autoconf",
    "automake", "pkg-config", "libtool",
    # Package managers / installers (shouldn't be in final image)
    "pip", "setuptools", "wheel", "npm", "yarn", "bundler",
    # Dev/test utilities
    "pytest", "unittest2", "nose", "coverage", "tox",
    "black", "flake8", "mypy", "pylint", "bandit",
    # Debugging tools
    "gdb", "strace", "ltrace", "valgrind",
    # Documentation generators
    "sphinx", "pdoc", "doxygen",
}

# Ecosystems where version pinning is most critical
PINNING_CRITICAL_ECOSYSTEMS = {"pypi", "pip", "npm", "yarn", "gem", "cargo"}

# Licenses that require legal review before distribution
RISKY_LICENSES = {
    "GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.0", "LGPL-2.1",
    "LGPL-3.0", "EUPL-1.1", "EUPL-1.2", "CC-BY-SA-4.0",
}

# Cap on components sent to LLM — the SBOM can have hundreds of entries
MAX_COMPONENTS_IN_PROMPT = 60


# ── Analysis helpers ──────────────────────────────────────────────────────────

def _cross_reference_vulns(
    components: list[SBOMComponent],
    vulnerabilities: list[Vulnerability],
) -> dict[str, list[str]]:
    """
    Build a map of package_name → [vuln_ids] by cross-referencing
    SBOM component names with vulnerability package names.

    Returns:
        Dict mapping component name (lowercase) to list of vuln IDs.
    """
    vuln_map: dict[str, list[str]] = defaultdict(list)

    for v in vulnerabilities:
        if v.package_name:
            key = v.package_name.lower()
            vuln_map[key].append(v.id)

    # Attach to components
    result = {}
    for comp in components:
        key = comp.name.lower()
        if key in vuln_map:
            result[comp.name] = vuln_map[key]

    return result


def _detect_dev_packages(
    components: list[SBOMComponent],
) -> list[SBOMComponent]:
    """Flag components that are likely build/dev tools present in final image."""
    flagged = []
    for comp in components:
        if comp.name.lower() in KNOWN_DEV_PACKAGES:
            flagged.append(comp)
    return flagged


def _detect_unpinned(
    components: list[SBOMComponent],
) -> list[SBOMComponent]:
    """
    Flag components with imprecise version strings.
    Unpinned versions (e.g. ranges, 'latest', empty) are a supply chain risk.
    """
    unpinned = []
    for comp in components:
        v = comp.version.strip()
        # Unpinned indicators
        if (
            not v
            or v in ("latest", "stable", "current", "*", "any")
            or v.startswith(("^", "~", ">", "<", ">=", "<="))
            or "||" in v
            or "x" in v.lower().split(".")
        ):
            if comp.ecosystem in PINNING_CRITICAL_ECOSYSTEMS:
                unpinned.append(comp)
    return unpinned


def _detect_duplicate_packages(
    components: list[SBOMComponent],
) -> dict[str, list[SBOMComponent]]:
    """
    Detect multiple versions of the same package installed simultaneously.
    This often indicates dependency conflicts or missed deduplication.

    Returns:
        Dict of package_name → [list of components] for packages with 2+ versions.
    """
    by_name: dict[str, list[SBOMComponent]] = defaultdict(list)
    for comp in components:
        by_name[comp.name.lower()].append(comp)

    return {
        name: comps
        for name, comps in by_name.items()
        if len(comps) > 1
    }


def _detect_risky_licenses(
    components: list[SBOMComponent],
) -> list[tuple[SBOMComponent, list[str]]]:
    """
    Flag components with licenses that may have legal implications
    for distribution or commercial use.

    Returns:
        List of (component, [risky_license_ids]) tuples.
    """
    flagged = []
    for comp in components:
        risky = [lic for lic in comp.licenses if lic in RISKY_LICENSES]
        if risky:
            flagged.append((comp, risky))
    return flagged


def _get_ecosystem_breakdown(
    components: list[SBOMComponent],
) -> dict[str, int]:
    """Count components by ecosystem."""
    breakdown: dict[str, int] = defaultdict(int)
    for comp in components:
        key = comp.ecosystem or "unknown"
        breakdown[key] += 1
    return dict(sorted(breakdown.items(), key=lambda x: x[1], reverse=True))


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_human_prompt(
    sbom: SBOM,
    vulnerable_components: dict[str, list[str]],
    dev_packages: list[SBOMComponent],
    unpinned: list[SBOMComponent],
    duplicates: dict[str, list[SBOMComponent]],
    risky_licenses: list[tuple[SBOMComponent, list[str]]],
    ecosystem_breakdown: dict[str, int],
    target_repo: str | None,
) -> str:
    """
    Build the SBOM optimization prompt from pre-analyzed data.
    Passes structured findings to LLM for report writing.
    """
    sections = []

    # ── Header ────────────────────────────────────────────────────────────────
    repo_label = target_repo or "target image"
    sections.append(f"SBOM OPTIMIZATION ANALYSIS FOR: {repo_label}")
    sections.append(f"Image: {sbom.image_name or 'N/A'}")
    sections.append(f"Total components: {sbom.total_components}")
    sections.append(f"Syft version: {sbom.syft_version or 'N/A'}")

    # ── Ecosystem breakdown ───────────────────────────────────────────────────
    sections.append("\nCOMPONENT ECOSYSTEM BREAKDOWN:")
    for ecosystem, count in ecosystem_breakdown.items():
        sections.append(f"  {ecosystem}: {count} packages")

    # ── Vulnerable components ─────────────────────────────────────────────────
    sections.append(
        f"\nVULNERABLE COMPONENTS ({len(vulnerable_components)} packages "
        f"have known vulnerabilities):"
    )
    if vulnerable_components:
        for pkg_name, vuln_ids in list(vulnerable_components.items())[:20]:
            sections.append(
                f"  - {pkg_name}: {len(vuln_ids)} vuln(s) "
                f"[{', '.join(vuln_ids[:3])}"
                f"{'...' if len(vuln_ids) > 3 else ''}]"
            )
    else:
        sections.append("  None — no SBOM components matched vulnerability data.")

    # ── Dev packages in final image ───────────────────────────────────────────
    sections.append(
        f"\nDEV/BUILD TOOLS IN FINAL IMAGE ({len(dev_packages)} found):"
    )
    if dev_packages:
        for comp in dev_packages:
            sections.append(
                f"  - {comp.name} {comp.version} "
                f"(ecosystem: {comp.ecosystem or 'unknown'}, "
                f"location: {comp.location or 'N/A'})"
            )
        sections.append(
            "  RECOMMENDATION: Move these to a build stage in a multi-stage Dockerfile."
        )
    else:
        sections.append("  None detected.")

    # ── Unpinned versions ─────────────────────────────────────────────────────
    sections.append(
        f"\nUNPINNED PACKAGE VERSIONS ({len(unpinned)} found):"
    )
    if unpinned:
        for comp in unpinned[:15]:
            sections.append(
                f"  - {comp.name} @ '{comp.version}' "
                f"(ecosystem: {comp.ecosystem or 'unknown'})"
            )
        if len(unpinned) > 15:
            sections.append(f"  ... and {len(unpinned) - 15} more.")
        sections.append(
            "  RECOMMENDATION: Pin all versions to exact strings for reproducibility."
        )
    else:
        sections.append("  None — all critical-ecosystem packages appear pinned.")

    # ── Duplicate packages ────────────────────────────────────────────────────
    sections.append(
        f"\nDUPLICATE PACKAGES (multiple versions installed): "
        f"{len(duplicates)} found"
    )
    if duplicates:
        for pkg_name, comps in list(duplicates.items())[:10]:
            versions = [c.version for c in comps]
            sections.append(
                f"  - {pkg_name}: versions {versions} "
                f"(ecosystems: {list({c.ecosystem for c in comps})})"
            )
        sections.append(
            "  RECOMMENDATION: Resolve to single version to reduce attack surface."
        )
    else:
        sections.append("  None detected.")

    # ── Risky licenses ────────────────────────────────────────────────────────
    sections.append(
        f"\nCOMPONENTS WITH RISKY LICENSES ({len(risky_licenses)} found):"
    )
    if risky_licenses:
        for comp, licenses in risky_licenses[:10]:
            sections.append(
                f"  - {comp.name} {comp.version}: {', '.join(licenses)}"
            )
        sections.append(
            "  RECOMMENDATION: Review legal requirements before distribution."
        )
    else:
        sections.append("  None detected.")

    # ── Sample of full component list ─────────────────────────────────────────
    # Send a capped sample so the LLM has context for the full picture
    sections.append(
        f"\nSAMPLE OF ALL COMPONENTS "
        f"(showing {min(MAX_COMPONENTS_IN_PROMPT, sbom.total_components)} "
        f"of {sbom.total_components}):"
    )
    for comp in sbom.components[:MAX_COMPONENTS_IN_PROMPT]:
        vuln_flag = (
            f" ⚠️ {len(vulnerable_components.get(comp.name, []))} vuln(s)"
            if comp.name in vulnerable_components
            else ""
        )
        sections.append(
            f"  - {comp.name} {comp.version} "
            f"[{comp.ecosystem or 'unknown'}]{vuln_flag}"
        )

    # ── Instruction ───────────────────────────────────────────────────────────
    sections.append(
        "\nWrite a professional SBOM optimization report in markdown format "
        "based on the above analysis. Structure it with these sections:\n"
        "1. SBOM Summary\n"
        "2. Vulnerable Components (prioritized list)\n"
        "3. Attack Surface Reduction Opportunities\n"
        "4. Dependency Health (unpinned, duplicates)\n"
        "5. License Compliance\n"
        "6. Recommended Actions (prioritized, numbered list)"
    )

    return "\n".join(sections)


# ── Fallback report ───────────────────────────────────────────────────────────

def _build_fallback_report(
    sbom: SBOM,
    vulnerable_components: dict[str, list[str]],
    dev_packages: list[SBOMComponent],
    unpinned: list[SBOMComponent],
    duplicates: dict[str, list[SBOMComponent]],
    error: str,
) -> str:
    """
    Minimal markdown report if the LLM call fails.
    Always gives the user something actionable.
    """
    lines = [
        "# SBOM Optimization Report",
        f"**Image:** {sbom.image_name or 'N/A'}",
        f"**Total components:** {sbom.total_components}",
        f"> ⚠️ LLM analysis failed ({error}). Showing raw analysis data.",
        "",
        "## Vulnerable Components",
        "",
    ]

    if vulnerable_components:
        for name, ids in vulnerable_components.items():
            lines.append(f"- **{name}**: {', '.join(ids[:3])}")
    else:
        lines.append("No vulnerable components detected.")

    lines += ["", "## Dev Tools in Final Image", ""]
    if dev_packages:
        for comp in dev_packages:
            lines.append(f"- `{comp.name}` {comp.version}")
    else:
        lines.append("None detected.")

    lines += ["", "## Unpinned Versions", ""]
    if unpinned:
        for comp in unpinned[:10]:
            lines.append(f"- `{comp.name}` @ `{comp.version}`")
    else:
        lines.append("None detected.")

    lines += ["", "## Duplicate Packages", ""]
    if duplicates:
        for name, comps in duplicates.items():
            lines.append(f"- `{name}`: {[c.version for c in comps]}")
    else:
        lines.append("None detected.")

    return "\n".join(lines)


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a container security and supply chain expert \
writing an SBOM (Software Bill of Materials) optimization report.

Your goal is to help developers reduce their container attack surface \
by identifying unnecessary, vulnerable, or poorly managed dependencies.

RULES:
1. Be specific and actionable. Name exact packages.
2. Prioritize by risk — vulnerable + in final image = highest priority.
3. Do not invent packages or vulnerabilities not present in the input.
4. For each recommendation, explain the security benefit clearly.
5. Keep the tone technical but concise — this is read by engineers.
6. Use markdown formatting with tables where appropriate.
7. The Recommended Actions section must be a numbered priority list."""


# ── Main node function ────────────────────────────────────────────────────────

def sbom_node(state: PipelineState) -> dict:
    """
    LangGraph node: SBOM Optimization Agent.

    Reads from state:
        - sbom: parsed SBOM from Syft
        - vulnerabilities: all normalized findings (for cross-referencing)
        - target_repo: name of scanned repository

    Writes to state:
        - sbom_optimization_report: markdown optimization report string
    """
    logger.info("SBOM node started.")

    # ── Edge case: no SBOM available ──────────────────────────────────────────
    if not state.sbom:
        logger.warning("SBOM node: no SBOM in state. Skipping.")
        return {
            "sbom_optimization_report": (
                "# SBOM Optimization Report\n\n"
                "⚠️ No SBOM data available. "
                "Ensure Syft ran successfully in the pipeline."
            )
        }

    sbom = state.sbom
    logger.info(f"SBOM node: analyzing {sbom.total_components} components.")

    # ── Step 1: Run all analysis passes ──────────────────────────────────────
    vulnerable_components = _cross_reference_vulns(
        sbom.components,
        state.vulnerabilities,
    )
    dev_packages       = _detect_dev_packages(sbom.components)
    unpinned           = _detect_unpinned(sbom.components)
    duplicates         = _detect_duplicate_packages(sbom.components)
    risky_licenses     = _detect_risky_licenses(sbom.components)
    ecosystem_breakdown = _get_ecosystem_breakdown(sbom.components)

    logger.info(
        f"SBOM analysis: "
        f"{len(vulnerable_components)} vulnerable components, "
        f"{len(dev_packages)} dev packages, "
        f"{len(unpinned)} unpinned, "
        f"{len(duplicates)} duplicates, "
        f"{len(risky_licenses)} risky licenses."
    )

    # ── Step 2: Build prompt ──────────────────────────────────────────────────
    human_prompt = _build_human_prompt(
        sbom=sbom,
        vulnerable_components=vulnerable_components,
        dev_packages=dev_packages,
        unpinned=unpinned,
        duplicates=duplicates,
        risky_licenses=risky_licenses,
        ecosystem_breakdown=ecosystem_breakdown,
        target_repo=state.target_repo,
    )

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=human_prompt),
    ]

    # ── Step 3: Call LLM ──────────────────────────────────────────────────────
    try:
        llm = get_llm()
        response = llm.invoke(messages)
        report = response.content.strip()
        logger.info("SBOM node complete. Report generated successfully.")

    except Exception as e:
        error_msg = f"LLM call failed: {e}"
        logger.error(f"SBOM node error: {error_msg}")
        report = _build_fallback_report(
            sbom=sbom,
            vulnerable_components=vulnerable_components,
            dev_packages=dev_packages,
            unpinned=unpinned,
            duplicates=duplicates,
            error=error_msg,
        )
        logger.info("SBOM node: fallback report generated.")

    return {"sbom_optimization_report": report}