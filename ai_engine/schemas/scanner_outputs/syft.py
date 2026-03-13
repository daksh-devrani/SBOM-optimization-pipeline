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
    value: Optional[str] = None
    spdxExpression: Optional[str] = None
    type: Optional[str] = None


class SyftLocation(BaseModel):
    path: str
    layerID: Optional[str] = None


class SyftCPE(BaseModel):
    cpe: str
    source: Optional[str] = None


class SyftArtifact(BaseModel):
    id: str
    name: str
    version: str
    type: str
    foundBy: Optional[str] = None
    locations: list[SyftLocation] = Field(default_factory=list)
    licenses: list[SyftLicense] = Field(default_factory=list)
    language: Optional[str] = None
    cpes: list[SyftCPE] = Field(default_factory=list)
    purl: Optional[str] = None


class SyftSource(BaseModel):
    type: str
    target: Optional[dict] = None


class SyftSchema(BaseModel):
    version: Optional[str] = None
    url: Optional[str] = None


class SyftOutput(BaseModel):
    schema: Optional[SyftSchema] = None
    artifacts: list[SyftArtifact] = Field(default_factory=list)
    source: Optional[SyftSource] = None
    distro: Optional[dict] = None
    descriptor: Optional[dict] = None
