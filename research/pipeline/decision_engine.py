"""
Decision engine: converts rule + LLM results into a final KEEP/REMOVE decision.

Logic:
  - If rule says FILTER → REMOVE (no LLM needed, confidence=1.0)
  - If rule says UNCERTAIN → use LLM result:
      - LLM says not exploitable AND confidence >= threshold → REMOVE
      - Otherwise → KEEP (safe default)
  - If UNCERTAIN but LLM unavailable → KEEP (safe default)
"""

from typing import Optional

from research.config.settings import get_settings
from research.models import FinalDecision, FinalLabel, LLMResult, RuleDecision, RuleResult, Vulnerability
from research.utils.logger import get_logger

logger = get_logger(__name__)


def make_decision(
    vulnerability: Vulnerability,
    rule_result: RuleResult,
    llm_result: Optional[LLMResult],
    confidence_threshold: Optional[float] = None,
) -> FinalDecision:
    """
    Produce the final KEEP or REMOVE decision for a vulnerability.

    Args:
        vulnerability:         The vulnerability being evaluated.
        rule_result:           Output from apply_rules().
        llm_result:            Output from validate_with_llm(), or None if not called.
        confidence_threshold:  Override the default threshold from settings.

    Returns:
        FinalDecision with label, explanation, confidence, and audit trail.
    """
    settings = get_settings()
    threshold = confidence_threshold if confidence_threshold is not None else settings.confidence_threshold

    # ── Rule-based decision (deterministic) ───────────────────────────────────
    if rule_result.decision == RuleDecision.FILTER:
        decision = FinalDecision(
            vulnerability_id=vulnerability.id,
            package=vulnerability.package,
            final_label=FinalLabel.REMOVE,
            explanation=rule_result.reason,
            confidence=1.0,
            method="rule",
            rule_result=rule_result,
            llm_result=None,
        )
        logger.info(
            "Rule-based decision: REMOVE",
            extra={
                "vulnerability_id": vulnerability.id,
                "fired_rule": rule_result.fired_rule,
            },
        )
        return decision

    # ── UNCERTAIN: LLM was not available ─────────────────────────────────────
    if llm_result is None:
        decision = FinalDecision(
            vulnerability_id=vulnerability.id,
            package=vulnerability.package,
            final_label=FinalLabel.KEEP,
            explanation=(
                "Rule result was UNCERTAIN but LLM validation was unavailable. "
                "Defaulting to KEEP (safe fallback)."
            ),
            confidence=0.0,
            method="llm",
            rule_result=rule_result,
            llm_result=None,
        )
        logger.info(
            "LLM unavailable — defaulting to KEEP",
            extra={"vulnerability_id": vulnerability.id},
        )
        return decision

    # ── LLM-based decision ────────────────────────────────────────────────────
    if not llm_result.exploitable and llm_result.confidence >= threshold:
        decision = FinalDecision(
            vulnerability_id=vulnerability.id,
            package=vulnerability.package,
            final_label=FinalLabel.REMOVE,
            explanation=(
                f"LLM determined not exploitable with confidence "
                f"{llm_result.confidence:.2f}: {llm_result.reasoning}"
            ),
            confidence=llm_result.confidence,
            method="llm",
            rule_result=rule_result,
            llm_result=llm_result,
        )
        logger.info(
            "LLM decision: REMOVE",
            extra={
                "vulnerability_id": vulnerability.id,
                "confidence": llm_result.confidence,
                "threshold": threshold,
            },
        )
    else:
        decision = FinalDecision(
            vulnerability_id=vulnerability.id,
            package=vulnerability.package,
            final_label=FinalLabel.KEEP,
            explanation=(
                f"LLM determined exploitable or confidence below threshold "
                f"({llm_result.confidence:.2f} < {threshold}): {llm_result.reasoning}"
            ),
            confidence=llm_result.confidence,
            method="llm",
            rule_result=rule_result,
            llm_result=llm_result,
        )
        logger.info(
            "LLM decision: KEEP",
            extra={
                "vulnerability_id": vulnerability.id,
                "exploitable": llm_result.exploitable,
                "confidence": llm_result.confidence,
                "threshold": threshold,
            },
        )

    return decision
