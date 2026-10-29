import base64
import binascii
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from app.services.auth import (
    DuplicateAccountError,
    SESSION_COOKIE,
    authenticate,
    create_account,
    current_user,
    clear_session_cookie,
    require_csrf,
    revoke_session,
    set_session_cookie,
)
from app.services.request_limits import enforce_request_limit


router = APIRouter(prefix="/api/auth", tags=["authentication"])
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
MAX_PDF_BYTES = 5 * 1024 * 1024


class SignupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        clean = " ".join(value.split())
        if len(clean) < 2:
            raise ValueError("Enter your name.")
        return clean

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        clean = value.strip().lower()
        if not EMAIL_PATTERN.fullmatch(clean):
            raise ValueError("Enter a valid email address.")
        return clean


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        clean = value.strip().lower()
        if not EMAIL_PATTERN.fullmatch(clean):
            raise ValueError("Enter a valid email address.")
        return clean


class ReportRequest(BaseModel):
    recipient: str = Field(min_length=3, max_length=254)
    report_type: Literal["email", "url"]
    pdf_base64: str = Field(min_length=8, max_length=7_000_000)

    @field_validator("recipient")
    @classmethod
    def valid_recipient(cls, value: str) -> str:
        clean = value.strip()
        if not EMAIL_PATTERN.fullmatch(clean):
            raise ValueError("Enter a valid recipient email address.")
        return clean


def _mail_settings() -> dict[str, str | int] | None:
    host = os.getenv("KESIHBA_SMTP_HOST", "").strip()
    username = os.getenv("KESIHBA_SMTP_USERNAME", "").strip()
    password = os.getenv("KESIHBA_SMTP_PASSWORD", "")
    sender = os.getenv("KESIHBA_SMTP_FROM", "").strip()
    if not all((host, username, password, sender)):
        return None
    if not EMAIL_PATTERN.fullmatch(sender):
        return None
    try:
        port = int(os.getenv("KESIHBA_SMTP_PORT", "587"))
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return {"host": host, "port": port, "username": username, "password": password, "sender": sender}


@router.get("/status")
def auth_status() -> dict[str, bool]:
    return {"email_delivery_configured": _mail_settings() is not None}


@router.get("/me")
def me(request: Request) -> dict[str, object]:
    return {"user": current_user(request)}


@router.post("/signup")
def signup(payload: SignupRequest, request: Request) -> dict[str, object]:
    enforce_request_limit(request, "auth-signup", limit=5, window_seconds=300)
    require_csrf(request)
    try:
        create_account(payload.name, payload.email, payload.password)
    except DuplicateAccountError:
        pass
    return {
        "user": None,
        "message": "If this email was available, the account is ready. Log in to continue; if you already had an account, use your current password.",
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, object]:
    enforce_request_limit(request, "auth-login", limit=8, window_seconds=300)
    require_csrf(request)
    result = authenticate(payload.email, payload.password)
    if result is None:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    user, token = result
    set_session_cookie(response, token)
    return {"user": user, "message": "You are signed in."}


@router.post("/logout")
def logout(request: Request, response: Response) -> dict[str, str]:
    require_csrf(request)
    revoke_session(request.cookies.get(SESSION_COOKIE))
    clear_session_cookie(response)
    return {"message": "You are signed out."}


@router.post("/send-report")
def send_report(payload: ReportRequest, request: Request) -> dict[str, str]:
    enforce_request_limit(request, "email-report", limit=10, window_seconds=60)
    require_csrf(request)
    user = current_user(request, required=True)
    settings = _mail_settings()
    if settings is None:
        raise HTTPException(status_code=503, detail="Email delivery is not configured on this server.")
    try:
        pdf = base64.b64decode(payload.pdf_base64, validate=True)
    except (binascii.Error, ValueError) as error:
        raise HTTPException(status_code=422, detail="The PDF report could not be read.") from error
    if len(pdf) > MAX_PDF_BYTES or not pdf.startswith(b"%PDF-"):
        raise HTTPException(status_code=422, detail="The PDF report is invalid or exceeds the 5 MB limit.")

    kind = payload.report_type.capitalize()
    filename = f"KESIHBA-{payload.report_type}-report.pdf"
    message = EmailMessage()
    message["Subject"] = f"KESIHBA {kind} Security Report"
    message["From"] = str(settings["sender"])
    message["To"] = payload.recipient
    message.set_content(
        f"Attached is the KESIHBA {payload.report_type} security analysis report requested by {user['name']}."
    )
    message.add_attachment(pdf, maintype="application", subtype="pdf", filename=filename)

    try:
        with smtplib.SMTP(str(settings["host"]), int(settings["port"]), timeout=15) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            server.login(str(settings["username"]), str(settings["password"]))
            server.send_message(message)
    except (OSError, smtplib.SMTPException) as error:
        raise HTTPException(status_code=502, detail="The report could not be sent. Please try again later.") from error
    return {"message": f"Report sent to {payload.recipient}."}
