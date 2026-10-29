from typing import Literal

from pydantic import BaseModel, Field, field_validator


class EmailAnalysisRequest(BaseModel):
    sender: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=998)
    body: str = Field(min_length=1, max_length=200_000)
    headers: dict[str, str] = Field(default_factory=dict)


class URLAnalysisRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class BatchURLAnalysisRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=10)

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, urls: list[str]) -> list[str]:
        if any(not 3 <= len(url.strip()) <= 2048 for url in urls):
            raise ValueError("Each URL must contain between 3 and 2048 characters.")
        return [url.strip() for url in urls]


class BatchURLAnalysisResponse(BaseModel):
    results: list["URLAnalysisResponse"]
    total: int


class URLAnalysisResponse(BaseModel):
    url: str
    submitted_url: str | None = None
    normalized_url: str | None = None
    hostname: str | None = None
    url_components: dict[str, object] = Field(default_factory=dict)
    status: str | None = None
    risk_level: str | None = None
    category: str = "undetermined"
    confidence: float | None = None
    checks: dict[str, Literal["matched", "no_match", "error", "not_checked", "unknown", "completed"]] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    redirect_chain: list[dict[str, object]] = Field(default_factory=list)
    final_url: str | None = None
    model_prediction: str | None = None
    model_probability: float | None = None
    local_indicators: list[dict[str, object]] = Field(default_factory=list)
    threat_intelligence: dict[str, object] = Field(default_factory=dict)
    domain_intelligence: dict[str, object] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    scan_timestamp: str | None = None
    classification: str
    risk_score: int
    model_score: int | None = None
    model_used: bool = False
    model_note: str
    virustotal: dict[str, object] | None = None
    google_safe_browsing: dict[str, object] | None = None
    reputation_status: str
    threat_types: list[str]
    intelligence_sources: list[str]
    indicators: list[str]
    reasons: list[str]
    explanation: str
    recommendation: str


BatchURLAnalysisResponse.model_rebuild()


class EmailAnalysisResponse(BaseModel):
    classification: str
    risk_score: int
    threat_types: list[str]
    spam_score: int
    scam_score: int
    model_score: int | None = None
    model_used: bool = False
    model_note: str
    intelligence_sources: list[str]
    indicators: list[str]
    reasons: list[str]
    extracted_urls: list[str]
    embedded_url_results: list[URLAnalysisResponse] = Field(default_factory=list)
    risk_breakdown: dict[str, int]
    headers: dict[str, str]
    explanation: str
    recommendation: str
    email_category: str = "unknown"
    category_evidence: list[str] = Field(default_factory=list)
    security_verdict: str = "inconclusive"
    threat_assessment: list[str] = Field(default_factory=list)
    model_probability: float | None = None
    calibrated_probability: float | None = None
    heuristic_risk_score: int | None = None


class ScanHistoryItem(BaseModel):
    id: int
    created_at: str
    scan_type: str
    target: str
    classification: str
    risk_score: int
    threat_types: list[str]
    indicators: list[str]
    source_count: int


class ScanSummaryResponse(BaseModel):
    counts: dict[str, int]
    recent: list[ScanHistoryItem]
