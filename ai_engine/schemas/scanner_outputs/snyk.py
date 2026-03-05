"""
Raw Snyk JSON output schema.
Snyk scans application dependencies for known vulnerabilities.
Output comes from `snyk test --json`.

Parse this into List[Vulnerability] using parsers/snyk_parser.py (next step).
"""

from typing import Optional
from pydantic import BaseModel, Field


class SnykSemVer(BaseModel):
    vulnerable: list[str] = Field(default_factory=list)  # Vulnerable version ranges


class SnykVulnerability(BaseModel):
    id: str                          # Snyk vuln ID e.g. "SNYK-PYTHON-REQUESTS-1234"
    title: str
    description: Optional[str] = None
    severity: str                    # "critical", "high", "medium", "low"
    cvssScore: Optional[float] = None
    identifiers: dict = Field(       # e.g. {"CVE": ["CVE-2023-32681"], "CWE": ["CWE-601"]}
        default_factory=dict
    )
    packageName: str
    version: str                     # Installed version
    fixedIn: list[str] = Field(      # Versions where fix is available
        default_factory=list
    )
    references: list[dict] = Field(  # [{"title": "...", "url": "..."}]
        default_factory=list
    )
    isUpgradable: bool = False
    isPatchable: bool = False


class SnykOutput(BaseModel):
    """Top-level structure of `snyk test --json` output."""
    ok: bool = False                 # True if no vulns found
    vulnerabilities: list[SnykVulnerability] = Field(default_factory=list)
    dependencyCount: Optional[int] = None
    packageManager: Optional[str] = None   # "pip", "npm", etc.
    projectName: Optional[str] = None