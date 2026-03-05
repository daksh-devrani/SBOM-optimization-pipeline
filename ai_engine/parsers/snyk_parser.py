"""
Snyk parser.
Converts `snyk test --json` output into List[Vulnerability].

Snyk focuses on application dependencies.
It uses its own IDs (SNYK-...) but also provides CVE cross-references.
We prefer the CVE ID if present, falling back to the Snyk ID.
"""

import json
import logging
from pathlib import Path
from typing import Union

from schemas.scanner_outputs.snyk import SnykOutput
from schemas.vulnerability import Vulnerability, Severity, FixStatus, VulnerabilitySource

logger = logging.getLogger(__name__)


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
}


def parse_snyk(filepath: Union[str, Path]) -> list[Vulnerability]:
    """
    Parse a Snyk JSON report into normalized Vulnerability objects.

    Args:
        filepath: Path to `snyk test --json` output.

    Returns:
        List of Vulnerability objects.
    """
    path = Path(filepath)

    if not path.exists():
        logger.warning(f"Snyk report not found: {filepath}")
        return []

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))

        # snyk test --json can return a list (monorepo) or a single object
        # Normalize to single object for now; handle list if needed
        if isinstance(raw, list):
            raw = raw[0] if raw else {}

        report = SnykOutput(**raw)
    except Exception as e:
        logger.error(f"Failed to parse Snyk report: {e}")
        return []

    vulns = []

    for sv in report.vulnerabilities:
        # Prefer CVE ID over Snyk's own ID
        cve_ids = sv.identifiers.get("CVE", [])
        vuln_id = cve_ids[0] if cve_ids else sv.id

        severity = SEVERITY_MAP.get(sv.severity.lower(), Severity.UNKNOWN)

        # Fix status from isUpgradable/isPatchable
        if sv.fixedIn:
            fix_status = FixStatus.FIXED
            fixed_version = sv.fixedIn[0]
        elif sv.isUpgradable or sv.isPatchable:
            fix_status = FixStatus.FIXED
            fixed_version = None
        else:
            fix_status = FixStatus.NOT_FIXED
            fixed_version = None

        # Extract reference URLs
        refs = [r.get("url", "") for r in sv.references if r.get("url")]

        vuln = Vulnerability(
            id=vuln_id,
            source=VulnerabilitySource.SNYK,
            package_name=sv.packageName,
            installed_version=sv.version,
            fixed_version=fixed_version,
            ecosystem=report.packageManager,
            severity=severity,
            cvss_score=sv.cvssScore,
            fix_status=fix_status,
            title=sv.title,
            description=sv.description,
            references=refs,
        )
        vulns.append(vuln)

    logger.info(f"Snyk: parsed {len(vulns)} vulnerabilities from {path.name}")
    return vulns