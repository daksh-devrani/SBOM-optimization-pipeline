"""
SBOM component model.
Represents a single package/component entry from a Syft-generated SBOM.
The SBOM Optimization Agent works exclusively with these models.
"""

from typing import Optional
from pydantic import BaseModel, Field


class SBOMComponent(BaseModel):
    """
    A single software component from the SBOM.
    Parsed from Syft's CycloneDX or SPDX JSON output.
    """

    # --- Identity ---
    name: str = Field(description="Package or library name.")
    version: str = Field(description="Installed version string.")
    purl: Optional[str] = Field(
        default=None,
        description="Package URL (purl). E.g. pkg:pypi/requests@2.28.0"
    )

    # --- Classification ---
    ecosystem: Optional[str] = Field(
        default=None,
        description="Ecosystem: 'pypi', 'npm', 'gem', 'cargo', 'apk', 'deb', etc."
    )
    component_type: Optional[str] = Field(
        default=None,
        description="Component type from SBOM: 'library', 'framework', 'application', 'os', etc."
    )

    # --- Source / location ---
    location: Optional[str] = Field(
        default=None,
        description="Where this package was found inside the container. E.g. '/usr/lib/python3/dist-packages'"
    )
    layer: Optional[str] = Field(
        default=None,
        description="Docker image layer digest where this package lives."
    )

    # --- Licensing ---
    licenses: list[str] = Field(
        default_factory=list,
        description="SPDX license identifiers. E.g. ['MIT', 'Apache-2.0']"
    )

    # --- Vulnerability linkage ---
    known_vulnerability_ids: list[str] = Field(
        default_factory=list,
        description="CVE/vuln IDs associated with this component (populated after cross-referencing)."
    )

    class Config:
        use_enum_values = True


class SBOM(BaseModel):
    """
    Full parsed SBOM for a scanned image.
    """
    image_name: Optional[str] = Field(
        default=None,
        description="Docker image name that was scanned."
    )
    image_digest: Optional[str] = Field(
        default=None,
        description="SHA256 digest of the scanned image."
    )
    syft_version: Optional[str] = Field(
        default=None,
        description="Version of Syft that generated this SBOM."
    )
    components: list[SBOMComponent] = Field(
        default_factory=list,
        description="All software components found in the image."
    )
    total_components: int = Field(
        default=0,
        description="Total count of components. Computed from len(components)."
    )