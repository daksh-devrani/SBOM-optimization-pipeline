"""
End-to-end LangGraph run without calling Groq.

When there are no vulnerabilities, no SBOM, and validation paths are empty,
fix_node, summary_node, and sbom_node skip LLM; validation_node skips research.
No GROQ_API_KEY is required.
"""

import os

import pytest

from schemas.pipeline_state import PipelineState
from workflow.graph import build_graph


@pytest.fixture(autouse=True)
def clear_groq_key(monkeypatch):
    """Ensure a stray env key does not mask missing-key failures in other tests."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


def test_full_graph_completes_without_llm_or_api_key():
    os.environ.pop("GROQ_API_KEY", None)

    initial = PipelineState(
        vulnerabilities=[],
        sbom=None,
        target_repo="smoke-test",
        trivy_report_path="",
        sbom_report_path="",
        repo_path="",
    )

    app = build_graph()
    final_dict = app.invoke(initial.model_dump())
    final = PipelineState(**final_dict)

    assert final.summary_report is not None
    assert "No vulnerabilities" in final.summary_report or "no vulnerabilities" in final.summary_report.lower()
    assert final.sbom_optimization_report is not None
    assert final.validation_report is None
    assert final.validation_errors
