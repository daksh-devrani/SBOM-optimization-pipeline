# SBOM Vulnerability Validation Pipeline

This project implements a comprehensive SBOM (Software Bill of Materials) Vulnerability Validation System. It integrates static analysis, rule-based evaluation, and LLM (Large Language Model) validation to assess the security of software packages.

## Project Structure

The project is organized into several key directories and files:

- **research/**: Contains the core logic for the validation pipeline, including models, static analysis, rule evaluation, and LLM validation.
  - **config/**: Configuration settings for the pipeline.
  - **evaluation/**: Functions for evaluating the performance of the validation pipeline against ground truth labels.
  - **llm_validation/**: Logic for validating vulnerabilities using an LLM.
  - **models.py**: Data models used throughout the pipeline.
  - **pipeline/**: Orchestrates the validation process and manages the flow of data.
  - **rule_engine/**: Defines rules for evaluating vulnerabilities.
  - **static_analysis/**: Parses Python files to extract relevant information for analysis.
  - **utils/**: Utility functions, including logging.

- **ai_engine/**: Contains the integration with the LangGraph pipeline.
  - **nodes/**: Custom nodes for the LangGraph workflow.
  - **schemas/**: Pydantic schemas for managing state.
  - **workflow/**: Defines the workflow graph for the LangGraph pipeline.
  - **main.py**: Entry point for executing the pipeline.

- **.github/**: Contains GitHub Actions workflows for CI/CD.

## Features

- **Static Analysis**: Analyzes Python code to identify package usage and function calls.
- **Rule Evaluation**: Applies deterministic rules to assess vulnerabilities based on static analysis signals.
- **LLM Validation**: Uses an LLM to validate uncertain vulnerabilities and provide insights.
- **Metrics Evaluation**: Compares the performance of the validation pipeline against ground truth data.

## Getting Started

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd research-validation-pipeline
   ```

2. **Install Dependencies**:
   Ensure you have Python 3.13 or higher and install the required packages listed in `requirements.txt`.

3. **Run the Pipeline**:
   Execute the main application to start the validation process:
   ```bash
   python ai_engine/main.py --sbom <path-to-sbom> --trivy <path-to-trivy-report> --repo <path-to-repo>
   ```

4. **View Outputs**:
   The results will be saved in the specified output directory.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.