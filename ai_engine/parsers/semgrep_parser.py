"""
Semgrep parser.
Converts raw `semgrep --json` output into List[Vulnerability].

Semgrep is SAST — findings have no package names or CVEs.
Severity mapping: Semgrep uses ERROR/WARNING/INFO.
"""

import json
import logging
from pathlib import Path
from typing import Union

from schemas.scanner_output.semgrep import SemgrepOutput
from schemas.vulnerability import Vulnerability, Severity, FixStatus, VulnerabilitySource

logger = logging.getLogger(__name__)


# Semgrep severity → normalized Severity
SEVERITY_MAP = {
    "ERROR":   Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO":    Severity.INFO,
}


def parse_semgrep(filepath: Union[str, Path]) -> list[Vulnerability]:
    """
    Parse a semgrep JSON report file into normalized Vulnerability objects.

    Args:
        filepath: Path to semgrep --json output file.

    Returns:
        List of Vulnerability objects. Empty list if file is missing or malformed.
    """
    path = Path(filepath)

    if not path.exists():
        logger.warning(f"Semgrep report not found: {filepath}")
        return []

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        report = SemgrepOutput(**raw)
    except Exception as e:
        logger.error(f"Failed to parse Semgrep report: {e}")
        return []

    vulns = []

    for result in report.results:
        severity = SEVERITY_MAP.get(
            result.extra.severity.upper(),
            Severity.UNKNOWN
        )

        # Extract CWE/references from metadata if present
        metadata  = result.extra.metadata or {}
        cwe_list  = metadata.get("cwe", [])
        refs      = metadata.get("references", [])
        if isinstance(refs, str):
            refs = [refs]

        # Build a clean ID from the rule
        vuln_id = f"semgrep:{result.check_id}"

        vuln = Vulnerability(
            id=vuln_id,
            source=VulnerabilitySource.SEMGREP,
            severity=severity,
            fix_status=FixStatus.UNKNOWN,   # SAST findings have no package fix
            title=result.check_id.split(".")[-1].replace("-", " ").title(),
            description=result.extra.message,
            file_path=result.path,
            line_start=result.start.get("line"),
            line_end=result.end.get("line"),
            references=refs,
        )
        vulns.append(vuln)

    logger.info(f"Semgrep: parsed {len(vulns)} findings from {path.name}")
    return vulns