"""
Raw Trivy JSON output schema.
Trivy scans container images for OS package vulns AND application dependency vulns.

A single Trivy report contains multiple "Results", one per layer/ecosystem.
Each Result has a list of Vulnerabilities.

Parse this into List[Vulnerability] using parsers/trivy_parser.py (next step).
"""

from typing import Optional
from pydantic import BaseModel, Field


class TrivyCVSS(BaseModel):
    V2Score: Optional[float] = None
    V3Score: Optional[float] = None


class TrivyVulnerability(BaseModel):
    VulnerabilityID: str          # CVE ID e.g. "CVE-2023-32681"
    PkgName: str                  # Package name
    InstalledVersion: str
    FixedVersion: Optional[str] = None
    Severity: str                 # "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"
    Title: Optional[str] = None
    Description: Optional[str] = None
    References: list[str] = Field(default_factory=list)
    CVSS: Optional[dict] = None   # Keyed by source e.g. {"nvd": TrivyCVSS}
    Status: Optional[str] = None  # "fixed", "affected", "will_not_fix", "end_of_life"


class TrivyResult(BaseModel):
    Target: str                   # E.g. "python:3.11-slim (debian 11.6)" or "requirements.txt"
    Class: str                    # "os-pkgs" or "lang-pkgs"
    Type: Optional[str] = None    # "debian", "pip", "npm", etc.
    Vulnerabilities: list[TrivyVulnerability] = Field(default_factory=list)


class TrivyOutput(BaseModel):
    """Top-level structure of `trivy image --format json` output."""
    SchemaVersion: int = 2
    ArtifactName: Optional[str] = None   # Image name
    ArtifactType: Optional[str] = None   # "container_image"
    Results: list[TrivyResult] = Field(default_factory=list)