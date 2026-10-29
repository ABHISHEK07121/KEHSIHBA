from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from app.schemas.email import (
    BatchURLAnalysisRequest,
    BatchURLAnalysisResponse,
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    URLAnalysisRequest,
    URLAnalysisResponse,
)
from app.services.email_analyzer import analyze_email, analyze_url
from app.services.email_file_parser import parse_email_upload
from app.services.scan_history import record_scan
from app.services.request_limits import enforce_request_limit
from app.services.auth import current_user


router = APIRouter(prefix="/api/analyze", tags=["analysis"])
MAX_EMAIL_UPLOAD_BYTES = 10 * 1024 * 1024


@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email_route(
    request: Request,
    payload: EmailAnalysisRequest | None = None,
    file: UploadFile | None = File(default=None),
) -> EmailAnalysisResponse:
    enforce_request_limit(request, "analysis")

    if file is not None:
        content = await file.read(MAX_EMAIL_UPLOAD_BYTES + 1)
        if len(content) > MAX_EMAIL_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Email upload exceeds the 10 MiB limit.")
        try:
            payload = parse_email_upload(file.filename or "uploaded_email", content)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif payload is None:
        try:
            raw_body = await request.body()
            if raw_body:
                payload = EmailAnalysisRequest.model_validate_json(raw_body.decode("utf-8"))
        except Exception as exc:  # pragma: no cover - defensive error handling for malformed input
            raise HTTPException(status_code=400, detail="Provide either a JSON email payload or an uploaded email file.") from exc

    if payload is None:
        raise HTTPException(status_code=400, detail="Email analysis request body is required.")

    result = analyze_email(payload)
    user = current_user(request)
    target = payload.sender or payload.subject or "Pasted email"
    record_scan(
        "email",
        target,
        result.classification,
        result.risk_score,
        result.threat_types,
        result.indicators,
        len(result.intelligence_sources),
        user_id=user["id"] if user else None,
    )
    return result


@router.post("/url", response_model=URLAnalysisResponse)
def analyze_url_route(payload: URLAnalysisRequest, request: Request) -> URLAnalysisResponse:
    enforce_request_limit(request, "analysis")
    result = analyze_url(payload)
    user = current_user(request)
    record_scan(
        "website",
        result.url,
        result.classification,
        result.risk_score,
        result.threat_types,
        result.indicators,
        len(result.intelligence_sources),
        user_id=user["id"] if user else None,
    )
    return result


@router.post("/urls", response_model=BatchURLAnalysisResponse)
def analyze_urls_route(payload: BatchURLAnalysisRequest, request: Request) -> BatchURLAnalysisResponse:
    enforce_request_limit(request, "analysis")
    results = [analyze_url(URLAnalysisRequest(url=url)) for url in payload.urls]
    user = current_user(request)
    for result in results:
        record_scan(
            "website",
            result.url,
            result.classification,
            result.risk_score,
            result.threat_types,
            result.indicators,
            len(result.intelligence_sources),
            user_id=user["id"] if user else None,
        )
    return BatchURLAnalysisResponse(results=results, total=len(results))
