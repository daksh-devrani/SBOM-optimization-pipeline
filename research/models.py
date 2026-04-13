"""
Core data models for the SBOM Vulnerability Validation System.

Single source of truth for all data structures used across the research pipeline.
All models use Pydantic v2 BaseModel. Enums use (str, Enum) for JSON serialization.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class RuleDecision(str, Enum):
    ALLOW = "ALLOW"        # Reserved for future use
    FILTER = "FILTER"      # Deterministically safe to remove
    UNCERTAIN = "UNCERTAIN"  # Needs LLM validation


class FinalLabel(str, Enum):
    KEEP = "KEEP"
    REMOVE = "REMOVE"


class Vulnerability(BaseModel):
    id: str = Field(description="CVE ID e.g. 'CVE-2023-1234'")
    package: str = Field(description="Package name e.g. 'requests'")
    version: str = Field(description="Installed version e.g. '2.27.1'")
    severity: str = Field(description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    description: str = Field(description="Full CVE description text")
    affected_functions: list[str] = Field(
        default_factory=list,
        description="Affected function names e.g. ['requests.get', 'requests.post']"
    )


class StaticSignals(BaseModel):
    package_used: bool = Field(description="Was the package imported anywhere in repo?")
    function_used: bool = Field(description="Was any affected_function called anywhere?")
    call_path_exists: bool = Field(description="Is there a traceable call chain to the function?")
    import_locations: list[str] = Field(
        default_factory=list,
        description="File paths where package is imported"
    )
    function_locations: list[str] = Field(
        default_factory=list,
        description="File paths where affected function is called"
    )
    input_controlled: bool = Field(description="Does user-controlled data reach the function?")
    sanitized: bool = Field(description="Is there sanitization before the call?")


class RuleResult(BaseModel):
    decision: RuleDecision
    reason: str = Field(description="Human-readable explanation of which rule fired")
    fired_rule: str = Field(description="Rule identifier e.g. 'Rule1_PackageNotUsed'")


class LLMResult(BaseModel):
    exploitable: bool
    confidence: float = Field(description="Confidence level between 0.0 and 1.0")
    reasoning: str
    raw_response: str = Field(description="Full raw LLM response string for audit")


class FinalDecision(BaseModel):
    vulnerability_id: str
    package: str
    final_label: FinalLabel
    explanation: str
    confidence: float = Field(description="1.0 if rule-based, LLM confidence if LLM-based")
    method: str = Field(description="Decision method: 'rule' or 'llm'")
    rule_result: RuleResult
    llm_result: Optional[LLMResult] = Field(default=None, description="LLM result if applicable")


class ValidationReport(BaseModel):
    total_input: int
    kept_count: int
    removed_count: int
    decisions: list[FinalDecision]
    errors: list[str] = Field(default_factory=list, description="Per-vulnerability errors encountered")
