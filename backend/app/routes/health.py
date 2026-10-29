from fastapi import APIRouter, Query, Request

from app.schemas.email import ScanHistoryItem, ScanSummaryResponse
from app.services.model_metadata import model_metadata
from app.services.scan_history import list_scans, scan_summary
from app.services.threat_intelligence import threat_intelligence
from app.services.auth import current_user


router = APIRouter(tags=["system"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "kesihba-backend"}


@router.get("/api/intelligence/status")
def intelligence_status() -> dict[str, object]:
    # Cached for five minutes; this checks credentials using a public example URL.
    threat_intelligence.check_virustotal_connection()
    return threat_intelligence.status()


@router.get("/api/models")
def models() -> dict[str, object]:
    return model_metadata()


@router.get("/api/scans", response_model=list[ScanHistoryItem])
def scans(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    scan_type: str | None = Query(default=None, pattern="^(email|website)$"),
    classification: str | None = Query(default=None, pattern="^(safe|no known threat detected|suspicious|high[_ ]risk|malicious|unknown)$", min_length=4, max_length=64),
    search: str | None = Query(default=None, max_length=200),
) -> list[dict[str, object]]:
    user = current_user(request, required=True)
    return list_scans(limit, scan_type, classification, search, user_id=user["id"])


@router.get("/api/scans/summary", response_model=ScanSummaryResponse)
def scans_summary(request: Request) -> dict[str, object]:
    user = current_user(request)
    return scan_summary(user_id=user["id"] if user else None)
