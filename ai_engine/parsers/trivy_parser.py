"""
Trivy parser.
Converts raw `trivy image --format json` output into List[Vulnerability].

Trivy scans both OS packages and application dependencies.
A single report has multiple Results (one per layer/ecosystem).
"""

import json
import logging
from pathlib import Path
from typing import Union

from schemas.scanner_outputs.trivy import TrivyOutput
from schemas.vulnerability import Vulnerability, Severity, FixStatus, VulnerabilitySource

logger = logging.getLogger(__name__)


SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "UNKNOWN":  Severity.UNKNOWN,
}

STATUS_MAP = {
    "fixed":        FixStatus.FIXED,
    "affected":     FixStatus.NOT_FIXED,
    "will_not_fix": FixStatus.WONT_FIX,
    "end_of_life":  FixStatus.WONT_FIX,
}


def _extract_cvss(cvss_dict: dict | None) -> float | None:
    """Pull the highest available CVSS score from Trivy's nested CVSS dict."""
    if not cvss_dict:
        return None
    best = None
    for source_scores in cvss_dict.values():
        for key in ("V3Score", "V2Score"):
            score = source_scores.get(key)
            if score is not None:
                if best is None or score > best:
                    best = score
    return best


def _infer_ecosystem(result_type: str | None) -> str | None:
    """Map Trivy's result type to a clean ecosystem string."""
    if not result_type:
        return None
    mapping = {
        "debian": "os",  "ubuntu": "os",  "alpine": "os",
        "redhat": "os",  "centos": "os",  "amazon": "os",
        "pip":    "pip", "pipenv": "pip", "poetry": "pip",
        "npm":    "npm", "yarn":   "npm",
        "bundler":"gem",
        "cargo":  "cargo",
        "gomod":  "go",
        "composer": "composer",
        "jar":    "maven",
    }
    return mapping.get(result_type.lower(), result_type.lower())


def parse_trivy(filepath: Union[str, Path]) -> list[Vulnerability]:
    """
    Parse a trivy JSON report into normalized Vulnerability objects.

    Args:
        filepath: Path to `trivy image --format json` output.

    Returns:
        List of Vulnerability objects.
    """
    path = Path(filepath)

    if not path.exists():
        logger.warning(f"Trivy report not found: {filepath}")
        return []

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        report = TrivyOutput(**raw)
    except Exception as e:
        logger.error(f"Failed to parse Trivy report: {e}")
        return []

    vulns = []

    for result in report.Results:
        ecosystem = _infer_ecosystem(result.Type)

        for tv in (result.Vulnerabilities or []):
            severity   = SEVERITY_MAP.get(tv.Severity.upper(), Severity.UNKNOWN)
            fix_status = STATUS_MAP.get(
                (tv.Status or "").lower(),
                FixStatus.FIXED if tv.FixedVersion else FixStatus.NOT_FIXED
            )
            cvss = _extract_cvss(tv.CVSS)

            vuln = Vulnerability(
                id=tv.VulnerabilityID,
                source=VulnerabilitySource.TRIVY,
                package_name=tv.PkgName,
                installed_version=tv.InstalledVersion,
                fixed_version=tv.FixedVersion or None,
                ecosystem=ecosystem,
                severity=severity,
                cvss_score=cvss,
                fix_status=fix_status,
                title=tv.Title,
                description=tv.Description,
                references=tv.References or [],
            )
            vulns.append(vuln)

    logger.info(f"Trivy: parsed {len(vulns)} vulnerabilities from {path.name}")
    return vulns