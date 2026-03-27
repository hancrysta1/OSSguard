from pydantic import BaseModel
from typing import Any, Optional


class AnalysisResponse(BaseModel):
    repository: str
    analysis_date: str
    security_overview: dict
    severity_distribution: list
    top_vulnerabilities: list


class PackageListResponse(BaseModel):
    repository: str
    analysis_date: str
    package_count: int
    packages: list


class VulnerabilityListResponse(BaseModel):
    repository: str
    analysis_date: str
    vulnerability_count: int
    vulnerabilities: list


class UpdateListResponse(BaseModel):
    repository: str
    analysis_date: str
    update_recommendations_count: int
    updates: list
