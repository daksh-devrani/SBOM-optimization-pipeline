"""
Syft parser.
Converts `syft -o cyclonedx-json` output into an SBOM object.

Syft generates the software inventory — it does NOT find vulnerabilities.
Its output feeds the SBOM Optimization Agent.
"""

import json
import logging
from pathlib import Path
from typing import Union

from schemas.scanner_outputs.syft import SyftOutput
from schemas.sbom import SBOM, SBOMComponent

logger = logging.getLogger(__name__)


def _extract_licenses(license_list: list) -> list[str]:
    """Pull SPDX license strings from Syft's license objects."""
    result = []
    for lic in license_list:
        if lic.spdxExpression:
            result.append(lic.spdxExpression)
        elif lic.value:
            result.append(lic.value)
    return result


def parse_syft(filepath: Union[str, Path]) -> SBOM | None:
    """
    Parse a Syft CycloneDX JSON SBOM into an SBOM object.

    Args:
        filepath: Path to `syft -o cyclonedx-json` output.

    Returns:
        SBOM object, or None if file is missing/malformed.
    """
    path = Path(filepath)

    if not path.exists():
        logger.warning(f"Syft SBOM not found: {filepath}")
        return None

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        report = SyftOutput(**raw)
    except Exception as e:
        logger.error(f"Failed to parse Syft SBOM: {e}")
        return None

    # Extract image metadata from source
    image_name   = None
    image_digest = None
    syft_version = None

    if report.source and report.source.target:
        target = report.source.target
        image_name   = target.get("userInput") or target.get("imageID")
        image_digest = target.get("manifestDigest") or target.get("digest")

    if report.descriptor:
        syft_version = report.descriptor.get("version")

    components = []
    for artifact in report.artifacts:
        # Get primary location path
        location = None
        layer    = None
        if artifact.locations:
            location = artifact.locations[0].path
            layer    = artifact.locations[0].layerID

        component = SBOMComponent(
            name=artifact.name,
            version=artifact.version,
            purl=artifact.purl,
            ecosystem=artifact.type,
            component_type="library",
            location=location,
            layer=layer,
            licenses=_extract_licenses(artifact.licenses),
        )
        components.append(component)

    sbom = SBOM(
        image_name=image_name,
        image_digest=image_digest,
        syft_version=syft_version,
        components=components,
        total_components=len(components),
    )

    logger.info(f"Syft: parsed {sbom.total_components} components from {path.name}")
    return sbom