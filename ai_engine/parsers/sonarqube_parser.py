"""
SonarQube parser.
Converts SonarQube API response into List[Vulnerability].

SonarQube is SAST — no CVEs, no package names.
We only pull issues of type VULNERABILITY or SECURITY_HOTSPOT.
Severity mapping: SonarQube uses BLOCKER/CRITICAL/MAJOR/MINOR/INFO.
"""

import json
import logging
from pathlib import Path
from typing import Union

from schemas.scanner_outputs.sonarqube import SonarQubeOutput
from schemas.vulnerability import Vulnerability, Severity, FixStatus, VulnerabilitySource

logger = logging.getLogger(__name__)


SEVERITY_MAP = {
    "BLOCKER":  Severity.CRITICAL,
    "CRITICAL": Severity.HIGH,
    "MAJOR":    Severity.MEDIUM,
    "MINOR":    Severity.LOW,
    "INFO":     Severity.INFO,
}

# Only import security-relevant issue types
SECURITY_TYPES = {"VULNERABILITY", "SECURITY_HOTSPOT"}


def _extract_file_path(component: str) -> str:
    """
    SonarQube component strings look like 'project-key:src/app.py'.
    Strip the project key prefix to get just the file path.
    """
    if ":" in component:
        return component.split(":", 1)[1]
    return component


def parse_sonarqube(filepath: Union[str, Path]) -> list[Vulnerability]:
    """
    Parse a SonarQube issues API response (saved as JSON) into Vulnerability objects.

    To save SonarQube output to a file in CI:
        curl -u $SONAR_TOKEN: \\
          "$SONAR_HOST/api/issues/search?projectKeys=$PROJECT_KEY&types=VULNERABILITY,SECURITY_HOTSPOT&resolved=false" \\
          -o sonarqube.json

    Args:
        filepath: Path to saved SonarQube API response JSON.

    Returns:
        List of Vulnerability objects.
    """
    path = Path(filepath)

    if not path.exists():
        logger.warning(f"SonarQube report not found: {filepath}")
        return []

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        report = SonarQubeOutput(**raw)
    except Exception as e:
        logger.error(f"Failed to parse SonarQube report: {e}")
        return []

    vulns = []

    for issue in report.issues:
        # Skip non-security issue types
        if issue.type not in SECURITY_TYPES:
            continue

        # Skip already resolved issues
        if issue.status in ("RESOLVED", "CLOSED"):
            continue

        severity = SEVERITY_MAP.get(issue.severity.upper(), Severity.UNKNOWN)
        file_path = _extract_file_path(issue.component)

        line_start = None
        line_end   = None
        if issue.textRange:
            line_start = issue.textRange.startLine
            line_end   = issue.textRange.endLine

        vuln = Vulnerability(
            id=f"sonarqube:{issue.rule}:{issue.key}",
            source=VulnerabilitySource.SONARQUBE,
            severity=severity,
            fix_status=FixStatus.UNKNOWN,   # SonarQube doesn't provide package fix info
            title=issue.rule,
            description=issue.message,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
        )
        vulns.append(vuln)

    logger.info(f"SonarQube: parsed {len(vulns)} security issues from {path.name}")
    return vulns