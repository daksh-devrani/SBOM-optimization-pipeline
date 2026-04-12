from pathlib import Path
import json
import argparse
from research.static_analysis.parser import parse_repository
from research.static_analysis.signals import compute_static_signals
from research.rule_engine.rules import apply_rules
from research.llm_validation.validator import validate_with_llm
from research.pipeline.decision_engine import make_decision
from research.utils.logger import get_logger
from research.models import ValidationReport, Vulnerability
from typing import List

logger = get_logger(__name__)

def load_trivy_vulnerabilities(trivy_path: str) -> List[Vulnerability]:
    with open(trivy_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    vulnerabilities = []
    for result in data.get("Results", []):
        vulns = result.get("Vulnerabilities") or []
        for vuln in vulns:
            vulnerabilities.append(Vulnerability(
                id=vuln["VulnerabilityID"],
                package=vuln["PkgName"],
                version=vuln.get("InstalledVersion", ""),
                severity=vuln.get("Severity", "UNKNOWN"),
                description=vuln.get("Description", ""),
                affected_functions=[]
            ))
    
    return list({(v.id, v.package): v for v in vulnerabilities}.values())

def load_sbom(sbom_path: str) -> dict:
    with open(sbom_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def run_pipeline(sbom_path: str, trivy_path: str, repo_path: str, output_dir: str, threshold: float, disable_llm: bool) -> ValidationReport:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    vulnerabilities = load_trivy_vulnerabilities(trivy_path)
    logger.info("Loaded vulnerabilities", extra={"count": len(vulnerabilities)})
    
    sbom = load_sbom(sbom_path)
    logger.info("Loaded SBOM", extra={"sbom": sbom})
    
    file_asts = parse_repository(repo_path)
    call_graph = build_basic_call_graph(file_asts)
    input_controlled = detect_input_sources(file_asts)
    sanitized = detect_sanitization(file_asts)
    
    decisions = []
    errors = []
    
    for vulnerability in vulnerabilities:
        try:
            signals = compute_static_signals(vulnerability, file_asts, call_graph)
            signals.input_controlled = input_controlled
            signals.sanitized = sanitized
            
            rule_result = apply_rules(signals)
            
            llm_result = None
            if rule_result.decision == RuleDecision.UNCERTAIN and not disable_llm:
                llm_result = validate_with_llm(vulnerability, signals)
            
            decision = make_decision(vulnerability, rule_result, llm_result, threshold)
            decisions.append(decision)
        except Exception as e:
            errors.append(str(e))
    
    report = ValidationReport(
        total_input=len(vulnerabilities),
        kept_count=len([d for d in decisions if d.final_label == FinalLabel.KEEP]),
        removed_count=len([d for d in decisions if d.final_label == FinalLabel.REMOVE]),
        decisions=[d.model_dump() for d in decisions],
        errors=errors
    )
    
    with open(Path(output_dir) / "filtered_vulnerabilities.json", 'w', encoding='utf-8') as f:
        json.dump([d.model_dump() for d in decisions if d.final_label == FinalLabel.KEEP], f, indent=2)
    
    with open(Path(output_dir) / "removed_vulnerabilities.json", 'w', encoding='utf-8') as f:
        json.dump([d.model_dump() for d in decisions if d.final_label == FinalLabel.REMOVE], f, indent=2)
    
    with open(Path(output_dir) / "detailed_log.json", 'w', encoding='utf-8') as f:
        json.dump([d.model_dump() for d in decisions], f, indent=2)
    
    with open(Path(output_dir) / "validation_report.json", 'w', encoding='utf-8') as f:
        json.dump(report.model_dump(), f, indent=2)
    
    return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the validation pipeline.")
    parser.add_argument("--sbom", required=True, help="Path to Syft SBOM JSON file")
    parser.add_argument("--trivy", required=True, help="Path to Trivy vulnerability JSON file")
    parser.add_argument("--repo", required=True, help="Path to target repository directory")
    parser.add_argument("--output-dir", default="research_outputs", help="Path to output directory")
    parser.add_argument("--threshold", type=float, default=0.75, help="Confidence threshold for LLM decisions")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM calls entirely")
    
    args = parser.parse_args()
    run_pipeline(args.sbom, args.trivy, args.repo, args.output_dir, args.threshold, args.no_llm)