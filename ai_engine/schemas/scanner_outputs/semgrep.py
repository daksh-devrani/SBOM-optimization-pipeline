"""
Raw Semgrep JSON output schema.
Semgrep is a SAST tool — it finds code-level issues, not package vulnerabilities.
Its output does NOT have package names or CVEs — only rule IDs and file locations.

Parse this into List[Vulnerability] using the parser in parsers/semgrep_parser.py (next step).
"""

from typing import Optional
from pydantic import BaseModel, Field


class SemgrepLocation(BaseModel):
    path: str
    start: dict  # {"line": int, "col": int, "offset": int}
    end: dict    # {"line": int, "col": int, "offset": int}


class SemgrepExtra(BaseModel):
    message: str
    severity: str        # "ERROR", "WARNING", "INFO"
    metadata: dict = {}  # Contains "cwe", "owasp", "references", etc. — varies by rule


class SemgrepResult(BaseModel):
    check_id: str        # Rule ID e.g. "python.django.security.injection.tainted-sql-string"
    path: str            # File path
    start: dict
    end: dict
    extra: SemgrepExtra


class SemgrepOutput(BaseModel):
    """Top-level structure of `semgrep --json` output."""
    results: list[SemgrepResult] = Field(default_factory=list)
    errors: list[dict] = Field(default_factory=list)
    version: Optional[str] = None