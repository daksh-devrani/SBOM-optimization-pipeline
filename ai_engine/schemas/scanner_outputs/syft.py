"""
Raw Syft SBOM JSON output schema (CycloneDX-style simplified).
Syft generates SBOMs — it does NOT find vulnerabilities itself.
Its output feeds the SBOM Optimization Agent and cross-references with vuln data.

Output comes from: `syft <image> -o cyclonedx-json`

Parse this into SBOM using parsers/syft_parser.py (next step).
"""

from typing import Optional
from pydantic import BaseModel, Field


class SyftLicense(BaseModel):
    value: Optional[str] = None    # SPDX identifier e.g. "MIT"
    spdxExpression: Optional[str] = None
    type: Optional[str] = None     # "declared" or "concluded"


class SyftLocation(BaseModel):
    path: str
    layerID: Optional[str] = None  # Docker layer digest


class SyftArtifact(BaseModel):
    """A single software component found by Syft."""
    id: str
    name: str
    version: str
    type: str                      # "python", "deb", "npm", "go-module", etc.
    foundBy: Optional[str] = None  # Which cataloger found this
    locations: list[SyftLocation] = Field(default_factory=list)
    licenses: list[SyftLicense] = Field(default_factory=list)
    language: Optional[str] = None
    cpes: list[str] = Field(default_factory=list)   # CPE strings
    purl: Optional[str] = None                       # Package URL


class SyftSource(BaseModel):
    type: str              # "image", "directory", "file"
    target: Optional[dict] = None  # Contains image name, digest, tags


class SyftOutput(BaseModel):
    """Top-level structure of `syft -o cyclonedx-json` output."""
    schema_version: Optional[str] = Field(default=None, alias="schema")
    artifacts: list[SyftArtifact] = Field(default_factory=list)
    source: Optional[SyftSource] = None
    distro: Optional[dict] = None    # OS distro info
    descriptor: Optional[dict] = None  # Syft version metadata

    class Config:
        populate_by_name = True