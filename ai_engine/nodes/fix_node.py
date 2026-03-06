"""
Security Fixing Agent Node.

Responsibilities:
- Analyze normalized vulnerabilities from all scanners
- Generate safe, deterministic fix suggestions
- Never suggest logic changes, refactoring, or architectural changes
- Only suggest: dependency upgrades, base image pinning,
  non-root user enforcement, multi-stage build moves

LangGraph contract:
- Input:  PipelineState (reads: vulnerabilities, dockerfile_content)
- Output: dict with keys 'fixes' and 'fix_log' to merge into state
"""

import json
import logging
from langchain_core.messages import SystemMessage, HumanMessage

from config.llm import get_llm
from schemas.pipeline_state import PipelineState, FixSuggestion
from schemas.vulnerability import Vulnerability, Severity, FixStatus

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

# Only act on these severities — ignore LOW/INFO to reduce noise
ACTIONABLE_SEVERITIES = {
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
}

# Only suggest fixes when a patched version actually exists
FIXABLE_STATUSES = {
    FixStatus.FIXED,
}

# Hard cap on vulns sent to LLM per call — avoids token overflow
MAX_VULNS_PER_BATCH = 20


# ── Prompt templates ─────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a DevSecOps security engineer specializing in \
container and dependency security.

Your job is to analyze vulnerability reports and suggest SAFE, MINIMAL fixes.

STRICT RULES — you must follow these without exception:
1. Only suggest dependency version upgrades, base image pinning, \
non-root user additions, or moving dev tools to build stages.
2. NEVER suggest changes to application logic, business logic, \
or code architecture.
3. NEVER suggest removing features or changing APIs.
4. Only suggest a fix when a patched version is explicitly known.
5. Mark safe_to_automate as true ONLY for version pin/upgrade changes. \
Always false for Dockerfile changes.
6. Be concise. One fix per vulnerability. No duplicates.

You must respond with ONLY a valid JSON array. No explanation, no markdown, \
no code fences. Just the raw JSON array.

Each element in the array must have exactly these fields:
{
  "vulnerability_id": "string",
  "package_name": "string or null",
  "current_version": "string or null",
  "suggested_version": "string or null",
  "fix_type": "dependency_upgrade | base_image_pin | non_root_user | multi_stage_build | manual_review",
  "description": "string",
  "safe_to_automate": true | false
}"""


def _build_human_prompt(
    vulns: list[Vulnerability],
    dockerfile: str | None,
) -> str:
    """Build the user-facing prompt with vulnerability data."""

    vuln_lines = []
    for v in vulns:
        line = (
            f"- ID: {v.id}\n"
            f"  Source: {v.source}\n"
            f"  Severity: {v.severity}\n"
            f"  Package: {v.package_name or 'N/A'}\n"
            f"  Installed: {v.installed_version or 'N/A'}\n"
            f"  Fixed in: {v.fixed_version or 'N/A'}\n"
            f"  Ecosystem: {v.ecosystem or 'N/A'}\n"
            f"  Description: {(v.description or v.title or 'No description')[:200]}\n"
        )
        vuln_lines.append(line)

    vuln_block = "\n".join(vuln_lines)

    dockerfile_block = ""
    if dockerfile:
        # Truncate Dockerfile to avoid token overflow
        truncated = dockerfile[:3000]
        dockerfile_block = f"\n\nDOCKERFILE CONTENT:\n```\n{truncated}\n```"

    return (
        f"Analyze the following vulnerabilities and generate fix suggestions.\n\n"
        f"VULNERABILITIES ({len(vulns)} total):\n{vuln_block}"
        f"{dockerfile_block}\n\n"
        f"Respond with a JSON array of fix suggestions."
    )


# ── Filtering helpers ─────────────────────────────────────────────────────────

def _filter_actionable(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """
    Keep only vulnerabilities that are worth acting on:
    - Severity is CRITICAL, HIGH, or MEDIUM
    - A fix exists OR it's from a SAST tool (needs manual_review)

    SAST findings (Semgrep, SonarQube) always pass through since they
    don't have package fix_status — they go to manual_review.
    """
    sast_sources = {"semgrep", "sonarqube"}
    result = []

    for v in vulns:
        if v.severity not in ACTIONABLE_SEVERITIES:
            continue
        # Always include SAST findings for manual review
        if v.source in sast_sources:
            result.append(v)
            continue
        # For SCA findings, only include if a fix exists
        if v.fix_status in FIXABLE_STATUSES:
            result.append(v)

    return result


def _deduplicate(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """
    Remove duplicate vulnerability IDs.
    Multiple scanners often report the same CVE — keep the first occurrence
    but prefer the one with the most information.
    """
    seen = {}
    for v in vulns:
        if v.id not in seen:
            seen[v.id] = v
        else:
            # Prefer entry with a known fixed_version
            if v.fixed_version and not seen[v.id].fixed_version:
                seen[v.id] = v
    return list(seen.values())


def _sort_by_severity(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Sort vulnerabilities by severity — CRITICAL first."""
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH:     1,
        Severity.MEDIUM:   2,
        Severity.LOW:      3,
        Severity.INFO:     4,
        Severity.UNKNOWN:  5,
    }
    return sorted(vulns, key=lambda v: order.get(v.severity, 5))


# ── LLM response parser ───────────────────────────────────────────────────────

def _parse_llm_response(
    raw_text: str,
    fix_log: list[str],
) -> list[FixSuggestion]:
    """
    Parse JSON array from LLM response into FixSuggestion objects.

    LLMs sometimes wrap JSON in markdown fences despite being told not to.
    We strip those defensively before parsing.
    """
    text = raw_text.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        # Remove first and last fence lines
        text = "\n".join(
            line for line in lines
            if not line.strip().startswith("```")
        ).strip()

    try:
        raw_list = json.loads(text)
    except json.JSONDecodeError as e:
        fix_log.append(f"ERROR: LLM returned invalid JSON — {e}")
        fix_log.append(f"Raw response (first 500 chars): {raw_text[:500]}")
        return []

    if not isinstance(raw_list, list):
        fix_log.append("ERROR: LLM response was not a JSON array.")
        return []

    suggestions = []
    for item in raw_list:
        try:
            suggestion = FixSuggestion(**item)
            suggestions.append(suggestion)
        except Exception as e:
            fix_log.append(f"WARNING: Skipped malformed fix suggestion — {e}")
            continue

    return suggestions


# ── Main node function ────────────────────────────────────────────────────────

def fix_node(state: PipelineState) -> dict:
    """
    LangGraph node: Security Fixing Agent.

    Reads from state:
        - vulnerabilities: all normalized findings
        - dockerfile_content: raw Dockerfile text (optional)

    Writes to state:
        - fixes: list of FixSuggestion
        - fix_log: audit trail of what was done
    """
    fix_log: list[str] = []
    fixes:   list[FixSuggestion] = []

    fix_log.append(
        f"Fix agent started. "
        f"Total input vulnerabilities: {len(state.vulnerabilities)}"
    )

    # ── Step 1: Filter + deduplicate ─────────────────────────────────────────
    actionable = _filter_actionable(state.vulnerabilities)
    fix_log.append(
        f"After severity/status filter: {len(actionable)} actionable vulnerabilities."
    )

    deduplicated = _deduplicate(actionable)
    fix_log.append(
        f"After deduplication: {len(deduplicated)} unique vulnerabilities."
    )

    if not deduplicated:
        fix_log.append("No actionable vulnerabilities found. Skipping LLM call.")
        return {"fixes": [], "fix_log": fix_log}

    sorted_vulns = _sort_by_severity(deduplicated)

    # ── Step 2: Batch if needed ───────────────────────────────────────────────
    # If there are many vulns, process in batches to stay within token limits
    batches = [
        sorted_vulns[i : i + MAX_VULNS_PER_BATCH]
        for i in range(0, len(sorted_vulns), MAX_VULNS_PER_BATCH)
    ]
    fix_log.append(
        f"Processing {len(sorted_vulns)} vulns in {len(batches)} batch(es) "
        f"(max {MAX_VULNS_PER_BATCH} per batch)."
    )

    # ── Step 3: Call LLM for each batch ──────────────────────────────────────
    llm = get_llm()

    for batch_num, batch in enumerate(batches, start=1):
        fix_log.append(
            f"Batch {batch_num}/{len(batches)}: "
            f"sending {len(batch)} vulnerabilities to LLM."
        )

        human_prompt = _build_human_prompt(
            vulns=batch,
            dockerfile=state.dockerfile_content,
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=human_prompt),
        ]

        try:
            response = llm.invoke(messages)
            raw_text = response.content

            batch_fixes = _parse_llm_response(raw_text, fix_log)
            fixes.extend(batch_fixes)

            fix_log.append(
                f"Batch {batch_num}: LLM returned {len(batch_fixes)} fix suggestions."
            )

        except Exception as e:
            error_msg = f"ERROR in batch {batch_num}: LLM call failed — {e}"
            logger.error(error_msg)
            fix_log.append(error_msg)
            continue

    # ── Step 4: Summary ───────────────────────────────────────────────────────
    automatable = sum(1 for f in fixes if f.safe_to_automate)
    manual      = len(fixes) - automatable

    fix_log.append(
        f"Fix agent complete. "
        f"Total fixes: {len(fixes)} "
        f"({automatable} automatable, {manual} require manual review)."
    )

    logger.info(
        f"Fix node complete: {len(fixes)} suggestions "
        f"({automatable} automatable, {manual} manual)"
    )

    return {
        "fixes":   fixes,
        "fix_log": fix_log,
    }