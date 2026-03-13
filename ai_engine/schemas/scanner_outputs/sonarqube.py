"""
Raw SonarQube API response schema.
SonarQube is a SAST/code quality tool. Results are fetched via its REST API,
not a CLI JSON file. The relevant endpoint is:
  GET /api/issues/search?projectKeys=<key>&resolved=false

Parse this into List[Vulnerability] using parsers/sonarqube_parser.py (next step).
"""

from typing import Optional
from pydantic import BaseModel, Field


class SonarQubeTextRange(BaseModel):
    startLine: int
    endLine: int
    startOffset: Optional[int] = None
    endOffset: Optional[int] = None


class SonarQubeIssue(BaseModel):
    key: str                          # Unique issue key
    rule: str                         # Rule ID e.g. "python:S5131"
    severity: str                     # "BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"
    component: str                    # File path e.g. "my-project:src/app.py"
    project: str
    message: str                      # Human-readable description
    type: str                         # "BUG", "VULNERABILITY", "CODE_SMELL", "SECURITY_HOTSPOT"
    status: str                       # "OPEN", "CONFIRMED", "REOPENED", "RESOLVED", "CLOSED"
    textRange: Optional[SonarQubeTextRange] = None
    tags: list[str] = Field(default_factory=list)
    # SonarQube doesn't provide CVE IDs directly — rule IDs map to CWE/OWASP


class SonarQubePaging(BaseModel):
    pageIndex: int
    pageSize: int
    total: int


class SonarQubeOutput(BaseModel):
    """Top-level structure of SonarQube /api/issues/search response."""
    paging: Optional[SonarQubePaging] = None
    issues: list[SonarQubeIssue] = Field(default_factory=list)