"""Syft CycloneDX schema field maps without shadowing BaseModel.schema."""

import json
from pathlib import Path

import pytest

from parsers.syft_parser import parse_syft
from schemas.scanner_outputs.syft import SyftOutput


def test_syft_output_accepts_json_schema_key():
    raw = {
        "schema": {"version": "1.4", "url": "http://cyclonedx.org/schema/bom/1.4"},
        "artifacts": [],
    }
    report = SyftOutput(**raw)
    assert report.cyclone_schema is not None
    assert report.cyclone_schema.version == "1.4"


def test_parse_syft_minimal_file(tmp_path: Path):
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(
        json.dumps(
            {
                "schema": {"version": "1.4"},
                "artifacts": [
                    {
                        "id": "a1",
                        "name": "libc",
                        "version": "1.0",
                        "type": "deb",
                        "locations": [{"path": "/usr/lib"}],
                        "licenses": [],
                        "cpes": [],
                    }
                ],
                "source": {"type": "directory", "target": {}},
                "descriptor": {"version": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    sbom = parse_syft(sbom_path)
    assert sbom is not None
    assert sbom.total_components == 1
    assert sbom.components[0].name == "libc"
