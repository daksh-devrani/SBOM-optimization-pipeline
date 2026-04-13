from pydantic import BaseModel, Field
from typing import List, Optional

class PipelineState(BaseModel):
    validation_report: Optional[dict] = Field(default=None, description="Output of SBOM vulnerability validation pipeline")
    validation_errors: List[str] = Field(default_factory=list, description="Errors from validation node")
    trivy_report_path: str = Field(default="", description="Path to Trivy JSON report file")
    sbom_report_path: str = Field(default="", description="Path to Syft SBOM JSON file")