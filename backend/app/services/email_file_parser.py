import re
import subprocess
from html.parser import HTMLParser
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from io import BytesIO
from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError
from docx import Document
from docx.opc.exceptions import PackageNotFoundError
from PIL import Image

from app.schemas.email import EmailAnalysisRequest

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
MAX_OCR_ATTACHMENTS = 3
MAX_OCR_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_PARSED_TEXT_CHARACTERS = 200_000


class _EmailHTMLLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href and href.strip().lower().startswith(("http://", "https://")):
                self.links.append(href.strip())


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    pieces: list[str] = []
    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            try:
                text = part.decode(encoding or "utf-8", errors="replace")
            except LookupError:
                text = part.decode("utf-8", errors="replace")
        else:
            text = str(part)
        pieces.append(text)
    return "".join(pieces).strip()


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text)


def _read_text_payload(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        payload = part.get_payload() or ""
        if isinstance(payload, str):
            return payload
        return ""
    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")
    return str(payload)


def _parse_eml(raw: bytes, filename: str) -> EmailAnalysisRequest:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    sender = _decode_header(message.get("From"))
    subject = _decode_header(message.get("Subject"))
    parsed_headers = {
        "reply_to": _decode_header(message.get("Reply-To")),
        "return_path": _decode_header(message.get("Return-Path")),
        "authentication_results": _decode_header(message.get("Authentication-Results")),
        "received": _decode_header(message.get("Received")),
    }
    text_parts: list[str] = []
    html_parts: list[str] = []
    image_ocr_parts: list[str] = []
    parse_warnings: list[str] = []
    ocr_attempts = 0
    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        if content_type.startswith("image/") and (part.get_filename() or part.get("Content-Disposition") or part.get("Content-ID")):
            image_bytes = part.get_payload(decode=True) or b""
            if image_bytes and len(image_bytes) <= MAX_OCR_ATTACHMENT_BYTES and ocr_attempts < MAX_OCR_ATTACHMENTS:
                ocr_attempts += 1
                try:
                    from app.services.image_ocr import extract_text_from_image
                    image_text = extract_text_from_image(image_bytes)
                    if image_text:
                        label = _decode_header(part.get_filename()) or f"image attachment {ocr_attempts}"
                        image_ocr_parts.append(f"[Text recognized in email image attachment: {label}]\n{image_text}")
                except (
                    ImportError,
                    Image.DecompressionBombError,
                    OSError,
                    RuntimeError,
                    subprocess.SubprocessError,
                    ValueError,
                ):
                    parse_warnings.append("OCR failed for an email image attachment; its contents were not analyzed.")
            elif image_bytes:
                parse_warnings.append("An email image attachment was skipped because it exceeded OCR count or size limits.")
            continue
        if content_type.startswith("text/"):
            text = _read_text_payload(part)
            if content_type.lower() == "text/html":
                html_parts.append(text)
            else:
                text_parts.append(text)
    body = "\n".join(part for part in text_parts if part).strip()
    if not body:
        body = "\n".join(_strip_html(part) for part in html_parts if part).strip()
    linked_urls: list[str] = []
    for html in html_parts:
        parser = _EmailHTMLLinks()
        parser.feed(html)
        linked_urls.extend(parser.links)
    if linked_urls:
        body = f"{body}\n[Email hyperlink destinations]\n" + "\n".join(dict.fromkeys(linked_urls))
    if image_ocr_parts:
        body = f"{body}\n" + "\n".join(image_ocr_parts)
    if ocr_attempts:
        body += f"\n[Image OCR checked up to {MAX_OCR_ATTACHMENTS} supported attachments; files over {MAX_OCR_ATTACHMENT_BYTES // (1024 * 1024)} MB were skipped.]"
    if parse_warnings:
        body += "\n[Analysis limitation: " + " ".join(dict.fromkeys(parse_warnings)) + "]"
    if not body:
        body = f"Uploaded message file: {filename}"
    if not subject:
        subject = f"Uploaded email: {Path(filename).name}"
    if len(body) > MAX_PARSED_TEXT_CHARACTERS:
        body = body[:MAX_PARSED_TEXT_CHARACTERS]
        parse_warnings.append("Extracted email text was truncated at the analysis size limit.")
    if parse_warnings:
        parsed_headers["analysis_warnings"] = " ".join(dict.fromkeys(parse_warnings))
    return EmailAnalysisRequest(sender=sender, subject=subject, body=body, headers=parsed_headers)


def _parse_pdf(raw: bytes, filename: str) -> EmailAnalysisRequest:
    try:
        reader = PdfReader(BytesIO(raw))
        text_chunks: list[str] = []
        for page in reader.pages:
            page_text = page.extract_text() or ""
            if page_text:
                text_chunks.append(page_text)
        body = "\n".join(text_chunks).strip() or f"Uploaded PDF file: {filename}"
        return EmailAnalysisRequest(sender="", subject=f"Uploaded PDF: {Path(filename).name}", body=body)
    except (OSError, PdfReadError, ValueError) as exc:
        raise ValueError("The uploaded PDF could not be parsed safely.") from exc


def _parse_docx(raw: bytes, filename: str) -> EmailAnalysisRequest:
    try:
        document = Document(BytesIO(raw))
        body = "\n".join(paragraph.text for paragraph in document.paragraphs if paragraph.text).strip()
        if not body:
            body = f"Uploaded DOCX file: {filename}"
        return EmailAnalysisRequest(sender="", subject=f"Uploaded DOCX: {Path(filename).name}", body=body)
    except (KeyError, OSError, PackageNotFoundError, ValueError) as exc:
        raise ValueError("The uploaded DOCX file could not be parsed safely.") from exc


def _parse_doc(raw: bytes, filename: str) -> EmailAnalysisRequest:
    decoded = raw.decode("utf-8", errors="replace")
    body = decoded.strip() or f"Uploaded DOC file: {filename}"
    return EmailAnalysisRequest(sender="", subject=f"Uploaded DOC: {Path(filename).name}", body=body)


def _parse_text_upload(raw: bytes, filename: str) -> EmailAnalysisRequest:
    body = raw.decode("utf-8", errors="replace").strip() or f"Uploaded file: {filename}"
    return EmailAnalysisRequest(sender="", subject=f"Uploaded file: {Path(filename).name}", body=body)


def parse_email_upload(filename: str, raw: bytes) -> EmailAnalysisRequest:
    suffix = Path(filename).suffix.lower()
    if suffix == ".eml":
        payload = _parse_eml(raw, filename)
    elif suffix == ".pdf":
        payload = _parse_pdf(raw, filename)
    elif suffix == ".docx":
        payload = _parse_docx(raw, filename)
    elif suffix == ".doc":
        payload = _parse_doc(raw, filename)
    elif suffix in {".txt", ".html", ".htm"}:
        payload = _parse_text_upload(raw, filename)
    else:
        payload = _parse_text_upload(raw, filename)

    if len(payload.body) <= MAX_PARSED_TEXT_CHARACTERS:
        return payload
    headers = dict(payload.headers)
    existing_warnings = headers.get("analysis_warnings", "")
    warnings = [existing_warnings, "Extracted email text was truncated at the analysis size limit."]
    headers["analysis_warnings"] = " ".join(value for value in warnings if value)
    return payload.model_copy(update={"body": payload.body[:MAX_PARSED_TEXT_CHARACTERS], "headers": headers})
