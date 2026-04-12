from research.models import StaticSignals, RuleResult, RuleDecision

def rule_package_not_used(signals: StaticSignals) -> RuleResult | None:
    if not signals.package_used:
        return RuleResult(
            decision=RuleDecision.FILTER,
            reason="Package is not imported anywhere in the repository",
            fired_rule="Rule1_PackageNotUsed"
        )
    return None

def rule_function_not_used(signals: StaticSignals) -> RuleResult | None:
    if not signals.function_used:
        return RuleResult(
            decision=RuleDecision.FILTER,
            reason="No affected functions are called in the repository",
            fired_rule="Rule2_FunctionNotUsed"
        )
    return None

def rule_no_call_path(signals: StaticSignals) -> RuleResult | None:
    if not signals.call_path_exists:
        return RuleResult(
            decision=RuleDecision.FILTER,
            reason="No call path exists from application code to the vulnerable function",
            fired_rule="Rule3_NoCallPath"
        )
    return None

def rule_input_not_controlled(signals: StaticSignals) -> RuleResult | None:
    if not signals.input_controlled:
        return RuleResult(
            decision=RuleDecision.FILTER,
            reason="No user-controlled input sources detected that could reach the function",
            fired_rule="Rule4_InputNotControlled"
        )
    return None

def apply_rules(signals: StaticSignals) -> RuleResult:
    rules = [rule_package_not_used, rule_function_not_used, rule_no_call_path, rule_input_not_controlled]
    for rule in rules:
        result = rule(signals)
        if result is not None:
            return result
    return RuleResult(
        decision=RuleDecision.UNCERTAIN,
        reason="No deterministic rule matched",
        fired_rule="None"
    )