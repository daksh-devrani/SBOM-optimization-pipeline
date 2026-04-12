import json
import argparse
from pathlib import Path
from ai_engine.schemas.pipeline_state import PipelineState
from research.pipeline.run_validation import run_pipeline
from research.utils.logger import get_logger

logger = get_logger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Run the SBOM Vulnerability Validation Pipeline.")
    parser.add_argument("--sbom", required=True, help="Path to Syft SBOM JSON file")
    parser.add_argument("--trivy", required=True, help="Path to Trivy vulnerability JSON file")
    parser.add_argument("--repo", required=True, help="Path to target repository directory")
    parser.add_argument("--output-dir", default="research_outputs", help="Path to output directory")
    parser.add_argument("--threshold", type=float, default=0.75, help="Confidence threshold for LLM decisions")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM calls entirely")

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Starting validation pipeline", extra={"sbom_path": args.sbom, "trivy_path": args.trivy, "repo_path": args.repo})

    try:
        report = run_pipeline(
            sbom_path=args.sbom,
            trivy_path=args.trivy,
            repo_path=args.repo,
            output_dir=str(output_dir),
            threshold=args.threshold,
            disable_llm=args.no_llm
        )

        if report:
            (output_dir / "validation-report.json").write_text(
                json.dumps(report.model_dump(), indent=2), encoding="utf-8"
            )

        logger.info("Validation pipeline completed successfully", extra={"report": report})

    except Exception as e:
        logger.error("An error occurred during the validation pipeline", extra={"error": str(e)})

if __name__ == "__main__":
    main()