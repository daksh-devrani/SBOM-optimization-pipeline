"""
Security Summarization Agent Node.

Responsibilities:
- Reduce noise in raw vulnerability reports
- Group findings by severity and type
- Clearly separate auto-fixed issues from manual review items
- Produce a clean, actionable markdown security report

LangGraph contract:
- Input:  PipelineState (reads: vulnerabilities, fixes, fix_log, target_repo)
- Output: dict with key 'summary_report' to merge into state
"""

import logging
from collections import defaultdict
from langchain_core.messages import SystemMessage, HumanMessage

from config.llm import get_llm
from schemas.pipeline_state import PipelineState, FixSuggestion
from schemas.vulnerability import Vulnerability, Severity, VulnerabilitySource

logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────

# Severity display order in the report
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]

# Emoji indicators for the markdown report
SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
    Severity.UNKNOWN:  "⚫",
}


# ── Prompt templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior security engineer writing an executive-level \
security report for a DevSecOps pipeline.

Your report will be read by developers who need to understand:
1. What vulnerabilities exist in their container image
2. Which ones were automatically fixed by the pipeline
3. Which ones require their manual attention
4. What the overall security posture looks like

RULES:
1. Be concise and actionable. No unnecessary filler text.
2. Group findings logically — do not list every single CVE individually.
3. Highlight patterns: e.g. "8 vulnerabilities in outdated base image packages"
4. Use the fix suggestions provided to accurately report what was auto-fixed.
5. The manual review section must clearly explain WHY each item needs human attention.
6. End with a brief overall risk assessment (1-2 sentences).
7. Use markdown formatting. Use tables where appropriate.
8. Do NOT invent vulnerabilities or fixes not present in the input data.

Write the report now based on the data provided."""


def _build_human_prompt(
    vulnerabilities: list[Vulnerability],
    fixes: list[FixSuggestion],
    target_repo: str | None,
) -> str:
    """
    Build the summarization prompt from pipeline data.
    Pre-processes data into structured sections so the LLM
    focuses on writing, not counting.
    """

    # ── Pre-process: counts by severity ──────────────────────────────────────
    severity_counts: dict[str, int] = defaultdict(int)
    for v in vulnerabilities:
        severity_counts[v.severity] += 1

    # ── Pre-process: counts by source ────────────────────────────────────────
    source_counts: dict[str, int] = defaultdict(int)
    for v in vulnerabilities:
        source_counts[v.source] += 1

    # ── Pre-process: which vulns got a fix suggestion ─────────────────────────
    fixed_ids = {f.vulnerability_id for f in fixes}
    auto_fixed = [f for f in fixes if f.safe_to_automate]
    manual_fixes = [f for f in fixes if not f.safe_to_automate]

    # ── Pre-process: unfixed critical/high vulns ──────────────────────────────
    unfixed_critical_high = [
        v for v in vulnerabilities
        if v.severity in (Severity.CRITICAL, Severity.HIGH)
        and v.id not in fixed_ids
    ]

    # ── Pre-process: SAST findings grouped by file ────────────────────────────
    sast_by_file: dict[str, list[Vulnerability]] = defaultdict(list)
    sast_sources = {VulnerabilitySource.SEMGREP, VulnerabilitySource.SONARQUBE}
    for v in vulnerabilities:
        if v.source in sast_sources and v.file_path:
            sast_by_file[v.file_path].append(v)

    # ── Build prompt sections ─────────────────────────────────────────────────
    sections = []

    # Header
    repo_label = target_repo or "target repository"
    sections.append(f"SECURITY SCAN REPORT DATA FOR: {repo_label}")
    sections.append(f"Total vulnerabilities found: {len(vulnerabilities)}")

    # Severity breakdown table
    sections.append("\nSEVERITY BREAKDOWN:")
    for sev in SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count > 0:
            sections.append(f"  {sev}: {count}")

    # Scanner source breakdown
    sections.append("\nFINDINGS BY SCANNER:")
    for source, count in sorted(source_counts.items()):
        sections.append(f"  {source}: {count}")

    # Auto-fixed items
    sections.append(f"\nAUTO-FIXED BY PIPELINE ({len(auto_fixed)} items):")
    if auto_fixed:
        for fix in auto_fixed:
            sections.append(
                f"  - [{fix.fix_type}] {fix.vulnerability_id}: "
                f"{fix.package_name} {fix.current_version} → {fix.suggested_version}"
            )
    else:
        sections.append("  None")

    # Manual fix suggestions
    sections.append(f"\nMANUAL FIX SUGGESTIONS ({len(manual_fixes)} items):")
    if manual_fixes:
        for fix in manual_fixes:
            sections.append(
                f"  - [{fix.fix_type}] {fix.vulnerability_id}: {fix.description}"
            )
    else:
        sections.append("  None")

    # Unfixed critical/high vulns (no fix available yet)
    sections.append(
        f"\nUNFIXED CRITICAL/HIGH VULNERABILITIES ({len(unfixed_critical_high)} items):"
    )
    if unfixed_critical_high:
        for v in unfixed_critical_high[:15]:  # Cap at 15 to avoid token overflow
            sections.append(
                f"  - {v.id} | {v.severity} | "
                f"{v.package_name or 'N/A'} {v.installed_version or ''} | "
                f"Source: {v.source} | "
                f"{(v.title or v.description or 'No description')[:120]}"
            )
        if len(unfixed_critical_high) > 15:
            sections.append(
                f"  ... and {len(unfixed_critical_high) - 15} more."
            )
    else:
        sections.append("  None — all critical/high findings have fix suggestions.")

    # SAST findings by file
    if sast_by_file:
        sections.append(f"\nSAST FINDINGS BY FILE ({len(sast_by_file)} files affected):")
        for filepath, file_vulns in list(sast_by_file.items())[:10]:
            severities = [v.severity for v in file_vulns]
            worst = min(severities, key=lambda s: SEVERITY_ORDER.index(s))
            sections.append(
                f"  - {filepath}: {len(file_vulns)} issue(s), "
                f"worst severity: {worst}"
            )

    sections.append(
        "\nWrite a professional security summary report in markdown format "
        "based on the above data. Structure it with these sections:\n"
        "1. Executive Summary\n"
        "2. Findings Overview (table)\n"
        "3. Auto-Fixed Issues\n"
        "4. Manual Review Required\n"
        "5. Overall Risk Assessment"
    )

    return "\n".join(sections)


# ── Fallback report builder ───────────────────────────────────────────────────

def _build_fallback_report(
    vulnerabilities: list[Vulnerability],
    fixes: list[FixSuggestion],
    target_repo: str | None,
    error: str,
) -> str:
    """
    Build a basic markdown report without LLM if the API call fails.
    Ensures the pipeline always produces some output.
    """
    severity_counts: dict[str, int] = defaultdict(int)
    for v in vulnerabilities:
        severity_counts[v.severity] += 1

    auto_fixed  = [f for f in fixes if f.safe_to_automate]
    manual_fixes = [f for f in fixes if not f.safe_to_automate]

    lines = [
        f"# Security Summary Report",
        f"**Repository:** {target_repo or 'N/A'}",
        f"> ⚠️ LLM summarization failed ({error}). "
        f"This is a fallback report generated from raw data.",
        "",
        "## Findings Overview",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    for sev in SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count > 0:
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev} | {count} |")

    lines += [
        "",
        f"**Total vulnerabilities:** {len(vulnerabilities)}",
        "",
        "## Auto-Fixed Issues",
        "",
    ]

    if auto_fixed:
        for fix in auto_fixed:
            lines.append(
                f"- `{fix.vulnerability_id}` — "
                f"{fix.package_name} upgraded to `{fix.suggested_version}`"
            )
    else:
        lines.append("No auto-fixed issues.")

    lines += ["", "## Manual Review Required", ""]

    if manual_fixes:
        for fix in manual_fixes:
            lines.append(f"- `{fix.vulnerability_id}` — {fix.description}")
    else:
        lines.append("No manual review items.")

    return "\n".join(lines)


# ── Main node function ────────────────────────────────────────────────────────

def summary_node(state: PipelineState) -> dict:
    """
    LangGraph node: Security Summarization Agent.

    Reads from state:
        - vulnerabilities: all normalized findings
        - fixes: fix suggestions from fix_node
        - fix_log: audit trail from fix_node
        - target_repo: name of scanned repository

    Writes to state:
        - summary_report: markdown security report string
    """
    logger.info(
        f"Summary node started. "
        f"Vulnerabilities: {len(state.vulnerabilities)}, "
        f"Fixes: {len(state.fixes)}"
    )

    # ── Edge case: nothing to summarize ──────────────────────────────────────
    if not state.vulnerabilities:
        logger.info("No vulnerabilities to summarize.")
        report = (
            "# Security Summary Report\n\n"
            f"**Repository:** {state.target_repo or 'N/A'}\n\n"
            "✅ **No vulnerabilities found.** "
            "All scanners completed without findings."
        )
        return {"summary_report": report}

    # ── Build prompt ──────────────────────────────────────────────────────────
    human_prompt = _build_human_prompt(
        vulnerabilities=state.vulnerabilities,
        fixes=state.fixes,
        target_repo=state.target_repo,
    )

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=human_prompt),
    ]

    # ── Call LLM ──────────────────────────────────────────────────────────────
    try:
        llm = get_llm()
        response = llm.invoke(messages)
        report = response.content.strip()

        logger.info("Summary node complete. Report generated successfully.")

    except Exception as e:
        error_msg = f"LLM call failed: {e}"
        logger.error(f"Summary node error: {error_msg}")

        # Always produce a report — fall back to template if LLM fails
        report = _build_fallback_report(
            vulnerabilities=state.vulnerabilities,
            fixes=state.fixes,
            target_repo=state.target_repo,
            error=error_msg,
        )
        logger.info("Summary node: fallback report generated.")

    return {"summary_report": report}