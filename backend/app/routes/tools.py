import ipaddress

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.services.domain_intelligence import (
    check_ssl,
    expand_public_link,
    lookup_dns,
    lookup_domain_age,
    normalize_hostname,
)
from app.services.request_limits import enforce_request_limit
from app.services.threat_intelligence import threat_intelligence


router = APIRouter(prefix="/api/tools", tags=["security tools"])


class LinkExpansionRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    max_redirects: int = Field(default=5, ge=1, le=5)


def _hostname(value: str) -> str:
    try:
        return normalize_hostname(value)
    except (UnicodeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/dns")
def dns_lookup(
    request: Request,
    hostname: str = Query(min_length=3, max_length=253),
) -> dict[str, object]:
    enforce_request_limit(request, "security-tools")
    return lookup_dns(_hostname(hostname))


@router.get("/ssl")
def ssl_check(
    request: Request,
    hostname: str = Query(min_length=3, max_length=253),
) -> dict[str, object]:
    enforce_request_limit(request, "security-tools")
    return check_ssl(_hostname(hostname))


@router.get("/domain-age")
def domain_age(
    request: Request,
    hostname: str = Query(min_length=3, max_length=253),
) -> dict[str, object]:
    enforce_request_limit(request, "security-tools")
    return lookup_domain_age(_hostname(hostname))


@router.get("/ip-reputation")
def ip_reputation(
    request: Request,
    address: str = Query(min_length=3, max_length=45),
) -> dict[str, object]:
    enforce_request_limit(request, "security-tools")
    try:
        normalized = str(ipaddress.ip_address(address))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="Enter a valid IPv4 or IPv6 address.") from error
    return threat_intelligence.lookup_ip_virustotal(normalized)


@router.post("/link-expander")
def link_expander(request: Request, payload: LinkExpansionRequest) -> dict[str, object]:
    enforce_request_limit(request, "security-tools")
    try:
        return expand_public_link(payload.url, payload.max_redirects)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
