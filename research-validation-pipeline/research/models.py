from pydantic import BaseModel, Field
from enum import Enum
from typing import List, Optional

class RuleDecision(str, Enum):
    ALLOW = "ALLOW"
    FILTER = "FILTER"
    UNCERTAIN = "UNCERTAIN"

class FinalLabel(str, Enum):
    KEEP = "KEEP"
    REMOVE = "REMOVE"

class Vulnerability(BaseModel):
    id: str = Field(..., description="CVE ID e.g. 'CVE-2023-1234'")
    package: str = Field(..., description="Package name e.g. 'requests'")
    version: str = Field(..., description="Installed version e.g. '2.27.1'")
    severity: str = Field(..., description="Severity level e.g. 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'")
    description: str = Field(..., description="Full CVE description text")
    affected_functions: List[str] = Field(default=[], description="List of affected functions e.g. ['requests.get', 'requests.post']")

class StaticSignals(BaseModel):
    package_used: bool = Field(..., description="Was the package imported anywhere in repo?")
    function_used: bool = Field(..., description="Was any affected_function called anywhere?")
    call_path_exists: bool = Field(..., description="Is there a traceable call chain to the function?")
    import_locations: List[str] = Field(default=[], description="File paths where package is imported")
    function_locations: List[str] = Field(default=[], description="File paths where function is called")
    input_controlled: bool = Field(..., description="Does user-controlled data reach the function?")
    sanitized: bool = Field(..., description="Is there sanitization before the call?")

class RuleResult(BaseModel):
    decision: RuleDecision
    reason: str = Field(..., description="Human-readable explanation of which rule fired")
    fired_rule: str = Field(..., description="Identifier of the rule that fired")

class LLMResult(BaseModel):
    exploitable: bool
    confidence: float = Field(..., description="Confidence level between 0.0 and 1.0")
    reasoning: str
    raw_response: str = Field(..., description="Full raw LLM response string for audit")

class FinalDecision(BaseModel):
    vulnerability_id: str
    package: str
    final_label: FinalLabel
    explanation: str
    confidence: float = Field(..., description="1.0 if rule-based, LLM confidence if LLM-based")
    method: str = Field(..., description="Method used for decision: 'rule' or 'llm'")
    rule_result: RuleResult
    llm_result: Optional[LLMResult] = Field(default=None, description="LLM result if applicable")

class ValidationReport(BaseModel):
    total_input: int
    kept_count: int
    removed_count: int
    decisions: List[FinalDecision]
    errors: List[str] = Field(default=[], description="Any per-vulnerability errors")