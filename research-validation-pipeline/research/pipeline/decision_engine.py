from research.models import RuleResult, RuleDecision, LLMResult, FinalDecision, FinalLabel
from research.config.settings import get_settings

def make_decision(vulnerability, rule_result: RuleResult, llm_result: LLMResult | None, confidence_threshold: float | None = None) -> FinalDecision:
    settings = get_settings()
    threshold = confidence_threshold if confidence_threshold is not None else settings.confidence_threshold
    
    if rule_result.decision == RuleDecision.FILTER:
        return FinalDecision(
            vulnerability_id=vulnerability.id,
            package=vulnerability.package,
            final_label=FinalLabel.REMOVE,
            explanation=rule_result.reason,
            confidence=1.0,
            method="rule",
            rule_result=rule_result,
            llm_result=None
        )
    
    if llm_result is None:
        return FinalDecision(
            vulnerability_id=vulnerability.id,
            package=vulnerability.package,
            final_label=FinalLabel.KEEP,
            explanation="Rule result was UNCERTAIN but LLM validation was unavailable. Defaulting to KEEP.",
            confidence=0.0,
            method="llm",
            rule_result=rule_result,
            llm_result=None
        )
    
    if llm_result.exploitable == False and llm_result.confidence >= threshold:
        return FinalDecision(
            vulnerability_id=vulnerability.id,
            package=vulnerability.package,
            final_label=FinalLabel.REMOVE,
            explanation=f"LLM determined not exploitable with confidence {llm_result.confidence:.2f}: {llm_result.reasoning}",
            confidence=llm_result.confidence,
            method="llm",
            rule_result=rule_result,
            llm_result=llm_result
        )
    else:
        return FinalDecision(
            vulnerability_id=vulnerability.id,
            package=vulnerability.package,
            final_label=FinalLabel.KEEP,
            explanation=f"LLM determined exploitable or confidence below threshold ({llm_result.confidence:.2f} < {threshold}): {llm_result.reasoning}",
            confidence=llm_result.confidence,
            method="llm",
            rule_result=rule_result,
            llm_result=llm_result
        )