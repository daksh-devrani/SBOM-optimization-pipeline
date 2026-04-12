"""
Deterministic rule engine for vulnerability filtering.

Rules are evaluated in strict order and short-circuit on first match.
If no rule fires, the decision is UNCERTAIN and LLM validation is needed.

Rule priority (highest to lowest):
  Rule 1 — Package not used in codebase at all
  Rule 2 — Affected functions never called
  Rule 3 — No call path reaches the vulnerable function
  Rule 4 — No user-controlled input reaches the call site

Each rule function returns a RuleResult if it fires, or None to pass through.
"""

from typing import Optional

from research.models import RuleDecision, RuleResult, StaticSignals
from research.utils.logger import get_logger

logger = get_logger(__name__)


def rule_package_not_used(signals: StaticSignals) -> Optional[RuleResult]:
    """
    Rule 1: If the vulnerable package is not imported anywhere, filter it.

    A package that is never imported cannot be exploited, regardless of
    whether a CVE exists for it.
    """
    if not signals.package_used:
        return RuleResult(
            decision=RuleDecision.FILTER,
            reason="Package is not imported anywhere in the repository",
            fired_rule="Rule1_PackageNotUsed",
        )
    return None


def rule_function_not_used(signals: StaticSignals) -> Optional[RuleResult]:
    """
    Rule 2: If none of the affected functions are called, filter it.

    The vulnerability is tied to specific functions. If those functions
    are never invoked, the vulnerability cannot be triggered.
    """
    if not signals.function_used:
        return RuleResult(
            decision=RuleDecision.FILTER,
            reason="No affected functions are called anywhere in the repository",
            fired_rule="Rule2_FunctionNotUsed",
        )
    return None


def rule_no_call_path(signals: StaticSignals) -> Optional[RuleResult]:
    """
    Rule 3: If no call path exists from application code to the vulnerable
    function, filter it.

    Even if the function is defined, it must be reachable from the main
    execution flow to be exploitable.
    """
    if not signals.call_path_exists:
        return RuleResult(
            decision=RuleDecision.FILTER,
            reason="No call path exists from application code to the vulnerable function",
            fired_rule="Rule3_NoCallPath",
        )
    return None


def rule_input_not_controlled(signals: StaticSignals) -> Optional[RuleResult]:
    """
    Rule 4: If no user-controlled input sources are detected, filter it.

    Most vulnerabilities require attacker-controlled input to be exploitable.
    If no external input reaches the call site, the risk is significantly reduced.
    """
    if not signals.input_controlled:
        return RuleResult(
            decision=RuleDecision.FILTER,
            reason="No user-controlled input sources detected that could reach the function",
            fired_rule="Rule4_InputNotControlled",
        )
    return None


# Ordered list of rules — evaluated top-to-bottom, first match wins
_RULES = [
    rule_package_not_used,
    rule_function_not_used,
    rule_no_call_path,
    rule_input_not_controlled,
]


def apply_rules(signals: StaticSignals) -> RuleResult:
    """
    Evaluate all rules in order and return the first matching result.

    If no rule fires, returns UNCERTAIN — the vulnerability must be
    evaluated by the LLM validation module.

    Args:
        signals: StaticSignals computed for a specific vulnerability.

    Returns:
        RuleResult with the decision and the rule that fired (or UNCERTAIN).
    """
    for rule_fn in _RULES:
        result = rule_fn(signals)
        if result is not None:
            logger.info(
                "Rule fired",
                extra={
                    "rule": result.fired_rule,
                    "decision": result.decision,
                    "reason": result.reason,
                },
            )
            return result

    logger.info("No deterministic rule matched — escalating to LLM")
    return RuleResult(
        decision=RuleDecision.UNCERTAIN,
        reason="All static signals suggest possible usage but context is ambiguous",
        fired_rule="None",
    )
