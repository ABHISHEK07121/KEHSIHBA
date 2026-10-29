import re
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import math
from email.utils import parseaddr
from difflib import SequenceMatcher
from datetime import datetime, timezone
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from app.schemas.email import EmailAnalysisRequest, EmailAnalysisResponse, URLAnalysisRequest, URLAnalysisResponse
from app.services.domain_intelligence import analyze_domain, normalize_hostname
from app.services.email_classifier import email_classifier
from app.services.threat_intelligence import threat_intelligence
from app.services.url_classifier import url_classifier


URL_PATTERN = re.compile(
    r"(?<![\w@.-])(?:https?://|www\.)?"
    r"(?:[\w](?:[\w-]{0,61}[\w])?\.)+[\w-]{2,}"
    r"(?::\d{1,5})?(?:/[^\s<>\"']*)?(?:\?[^\s<>\"']*)?(?:#[^\s<>\"']*)?",
    re.IGNORECASE,
)
NON_URL_SUFFIXES = {
    "csv", "doc", "docx", "gif", "htm", "html", "jpeg", "jpg", "js",
    "json", "pdf", "png", "ppt", "pptx", "svg", "txt", "xls", "xlsx", "xml", "zip",
}
URGENT_TERMS = ("urgent", "immediately", "within 24 hours", "account suspended")
CREDENTIAL_TERMS = ("password", "login", "verify your account", "one-time code", "credentials")
PAYMENT_TERMS = ("gift card", "wire transfer", "payment", "invoice", "bank account")
SCAM_TERMS = (
    "gift card", "wire transfer", "crypto investment", "guaranteed returns", "recovery fee",
    "tax refund", "remote access", "upfront fee", "send money", "wallet seed phrase",
)
SPAM_TERMS = (
    "unsubscribe", "limited time offer", "promo code", "buy now", "special discount",
    "claim your prize", "exclusive offer", "act now", "free trial",
)
SUSPICIOUS_URL_TERMS = ("login", "verify", "secure", "account", "update", "wallet", "payment")
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly"}
BRAND_DOMAINS = {
    "amazon": ("amazon.com", "amazon.in"),
    "apple": ("apple.com",),
    "bhim": ("bhimupi.org.in",),
    "interbank": ("interbank.pe", "interbank.com.pe"),
    "bcp": ("viabcp.com", "bcp.com.pe"),
    "bbva": ("bbva.pe", "bbva.com"),
    "scotiabank": ("scotiabank.com.pe", "scotiabank.com"),
    "digilocker": ("digilocker.gov.in",),
    "facebook": ("facebook.com",),
    "google": ("google.com", "google.co.in"),
    "hdfc": ("hdfcbank.com", "hdfc.com"),
    "incometax": ("incometax.gov.in",),
    "instagram": ("instagram.com",),
    "irctc": ("irctc.co.in",),
    "microsoft": ("microsoft.com", "live.com", "office.com"),
    "mygov": ("mygov.in",),
    "npci": ("npci.org.in",),
    "paytm": ("paytm.com",),
    "paypal": ("paypal.com",),
    "phonepe": ("phonepe.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "santander": ("santander.com", "santander.com.pe"),
    "uidai": ("uidai.gov.in",),
}


def _urls(text: str) -> list[str]:
    urls: list[str] = []
    for match in URL_PATTERN.finditer(text):
        url = match.group().rstrip(".,!?;:)]}")
        hostname = (urlsplit(url if "://" in url else f"https://{url}").hostname or "").lower()
        if hostname.rsplit(".", 1)[-1] in NON_URL_SUFFIXES:
            continue
        urls.append(url)
    return list(dict.fromkeys(urls))


def _email_domain(sender: str) -> str:
    address = parseaddr(sender)[1]
    return address.rsplit("@", 1)[-1].lower().strip(".>") if "@" in address else ""


def _normalize_url(value: str) -> tuple[str, object | None, list[str]]:
    warnings: list[str] = []
    submitted = value.strip()
    if "://" not in submitted:
        submitted = f"https://{submitted}"
        warnings.append("No scheme was supplied; https:// was assumed for analysis.")
    try:
        parsed = urlsplit(submitted)
        if parsed.scheme.lower() not in {"http", "https"}:
            return submitted, parsed, ["Unsupported URL scheme. Only http and https are analyzed."]
        if not parsed.hostname:
            return submitted, parsed, ["URL is missing a hostname."]
        hostname = normalize_hostname(parsed.hostname)
        if parsed.username is not None or parsed.password is not None:
            warnings.append("The URL contains embedded credentials before the hostname; verify the destination carefully.")
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            return submitted, None, ["URL port is outside the valid range."]
        netloc = hostname
        if ":" in hostname and not hostname.startswith("["):
            netloc = f"[{hostname}]"
        if port:
            netloc = f"{netloc}:{port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")), parsed, warnings
    except (UnicodeError, ValueError):
        return submitted, None, ["URL is malformed and could not be parsed safely."]


def _url_features(normalized_url: str, parsed: object | None) -> dict[str, object]:
    split = urlsplit(normalized_url) if parsed is not None else None
    host = (split.hostname or "").lower() if split else ""
    labels = [label for label in host.split(".") if label]
    path_query = f"{split.path or ''}?{split.query or ''}" if split else ""
    decoded = unquote(normalized_url)
    has_ip = False
    if host:
        try:
            ipaddress.ip_address(host)
            has_ip = True
        except ValueError:
            has_ip = False
    suffix_size = 3 if len(labels) >= 3 and labels[-2] in {
        "ac", "co", "com", "edu", "gov", "net", "org", "res"
    } and len(labels[-1]) == 2 else 2
    registered_hint = ".".join(labels[-suffix_size:]) if labels else host
    registered_label = registered_hint.split(".", 1)[0]
    label_counts = {character: registered_label.count(character) for character in set(registered_label)}
    label_entropy = (
        -sum((count / len(registered_label)) * math.log2(count / len(registered_label)) for count in label_counts.values())
        if registered_label else 0.0
    )
    digit_count = sum(character.isdigit() for character in registered_label)
    longest_consonant_run = max(
        (len(run) for run in re.findall(r"[bcdfghjklmnpqrstvwxyz]+", registered_label)),
        default=0,
    )
    impersonated_brands = []
    for brand, official_domains in BRAND_DOMAINS.items():
        is_official_domain = any(
            registered_hint == official or registered_hint.endswith(f".{official}")
            for official in official_domains
        )
        brand_mentioned = brand in host
        lookalike_domain = SequenceMatcher(None, registered_label, brand).ratio() >= 0.78
        if not is_official_domain and (brand_mentioned or lookalike_domain):
            impersonated_brands.append(brand)
    external_redirect_parameter = False
    if split:
        for key, value in parse_qsl(split.query, keep_blank_values=True):
            if key.casefold() not in {"redirect", "redirect_uri", "return", "return_url", "next", "url", "continue"}:
                continue
            try:
                target = urlsplit(unquote(value))
                if (
                    target.scheme.lower() in {"http", "https"}
                    and target.hostname
                    and normalize_hostname(target.hostname) != host
                ):
                    external_redirect_parameter = True
                    break
            except (UnicodeError, ValueError):
                continue
    return {
        "url_length": len(normalized_url),
        "hostname_length": len(host),
        "num_subdomains": max(len(labels) - 2, 0),
        "has_ip_hostname": has_ip,
        "https_present": bool(split and split.scheme == "https"),
        "suspicious_encoding": "%" in normalized_url or decoded != normalized_url,
        "unusual_delimiters": any(token in normalized_url for token in ("@", "\\", "//http", "..")),
        "url_shortener": host in URL_SHORTENERS,
        "misleading_brand_impersonation": bool(impersonated_brands),
        "impersonated_brands": impersonated_brands,
        "unusual_registered_label": len(registered_label) >= 7 and longest_consonant_run >= 5,
        "high_entropy_registered_label": len(registered_label) >= 13 and label_entropy >= 3.55,
        "digit_heavy_registered_label": digit_count >= 4 and digit_count / max(len(registered_label), 1) >= 0.25,
        "nonstandard_port": bool(split and split.port and split.port not in {80, 443}),
        "executable_download": bool(
            split
            and split.path.rsplit("/", 1)[-1].rsplit(".", 1)[-1].casefold()
            in {"apk", "bat", "cmd", "dmg", "exe", "hta", "msi", "ps1", "scr", "vbs"}
            and "." in split.path.rsplit("/", 1)[-1]
        ),
        "external_redirect_parameter": external_redirect_parameter,
        "suspicious_hostname_patterns": any(term in host for term in SUSPICIOUS_URL_TERMS),
        "suspicious_path_patterns": any(term in path_query.lower() for term in SUSPICIOUS_URL_TERMS),
    }


def _add_indicator(
    indicators: list[str],
    local_indicators: list[dict[str, object]],
    reason: str,
    weight: int,
    category: str,
) -> int:
    indicators.append(reason)
    severity = "high" if weight >= 25 else "medium" if weight >= 12 else "low"
    local_indicators.append({"category": category, "weight": weight, "severity": severity, "reason": reason})
    return weight


def _classify_email_category(message_text: str, subject: str, extracted_urls: list[str]) -> tuple[str, list[str]]:
    combined = f"{subject}\n{message_text}".lower()
    evidence: list[str] = []

    if any(term in combined for term in ("limited time offer", "exclusive offer", "buy now", "promo code", "unsubscribe", "claim your prize", "special discount")):
        evidence.append("Promotional and unsubscribe language is present.")
        if any(term in combined for term in ("invoice", "receipt", "order confirmation", "password reset", "verification", "security alert")):
            return "newsletter_or_bulk", evidence
        return "marketing_promotional", evidence

    if any(term in combined for term in ("newsletter", "weekly digest", "monthly update", "subscription", "view in browser")):
        evidence.append("Newsletter or bulk-communication cues are present.")
        return "newsletter_or_bulk", evidence

    if any(term in combined for term in ("urgent", "account suspended", "verify your account", "login now", "password", "one-time code")):
        evidence.append("Credential or urgency cues suggest account-focused messaging.")
        return "personal_or_transactional", evidence

    if extracted_urls and len(extracted_urls) >= 1 and all("unsubscribe" not in combined and "promo" not in combined for _ in [0]):
        evidence.append("A direct link is present without clear promotional language.")
        return "unknown", evidence

    if any(term in combined for term in ("invoice", "receipt", "delivery", "appointment", "order", "reservation")):
        evidence.append("Transactional or personal email cues are present.")
        return "personal_or_transactional", evidence

    evidence.append("No strong marketing or threat cues were identified.")
    return "unknown", evidence


def _determine_security_verdict(classification: str, threat_types: set[str], email_category: str) -> str:
    threat_names = sorted(threat_types)
    if classification in {"Malicious", "High Risk"}:
        if "malware_distribution" in threat_names:
            return "Malware risk"
        if "phishing" in threat_names or "credential_theft" in threat_names or "financial_scam" in threat_names:
            return "High-risk phishing or scam"
        return "Suspicious"
    if classification == "Suspicious":
        return "Suspicious"
    if email_category in {"marketing_promotional", "newsletter_or_bulk"} and not threat_names:
        return "Likely legitimate / marketing"
    if "spam" in threat_names and not {"phishing", "credential_theft", "financial_scam"}.intersection(threat_names):
        return "Spam / unwanted"
    if threat_names:
        return "High-risk phishing or scam" if any(item in threat_names for item in {"phishing", "credential_theft", "financial_scam"}) else "Malware risk" if "malware_distribution" in threat_names else "Suspicious"
    return "Inconclusive"


def analyze_email(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:
    combined = f"{payload.subject}\n{payload.body}".lower()
    extracted_urls = _urls(payload.body)
    message_text = URL_PATTERN.sub(" ", combined)
    indicators: list[str] = []
    analysis_warnings = [
        warning.strip()
        for warning in payload.headers.get("analysis_warnings", "").split(";")
        if warning.strip()
    ]
    indicators.extend(f"Analysis limitation: {warning}" for warning in analysis_warnings)
    breakdown = {
        "url_indicators": 0,
        "sender_indicators": 0,
        "content_indicators": 0,
        "threat_intelligence": 0,
        "impersonation_indicators": 0,
    }
    threat_types: set[str] = set()
    intelligence_sources: set[str] = set()
    embedded_url_results: list[URLAnalysisResponse] = []
    scam_hits = sum(term in message_text for term in SCAM_TERMS)
    spam_hits = sum(term in message_text for term in SPAM_TERMS)
    scam_score = min(scam_hits * 20, 100)
    spam_score = min(spam_hits * 20, 100)

    if not payload.sender or "@" not in payload.sender:
        indicators.append("Sender address is missing or malformed.")
        breakdown["sender_indicators"] += 20

    if any(term in message_text for term in URGENT_TERMS):
        indicators.append("The message uses urgency or account-pressure language.")
        breakdown["content_indicators"] += 15

    if any(term in message_text for term in CREDENTIAL_TERMS):
        indicators.append("The message requests or references account credentials.")
        breakdown["content_indicators"] += 25
        threat_types.add("credential_theft")

    if any(term in message_text for term in PAYMENT_TERMS):
        indicators.append("The message contains payment or financial-request language.")
        breakdown["content_indicators"] += 20

    if scam_score:
        indicators.append("The message contains common payment, investment, or recovery-scam language.")
        breakdown["content_indicators"] += min(scam_score // 2, 30)
        threat_types.add("financial_scam")

    if spam_score >= 40:
        indicators.append("The message contains promotional or unsolicited-marketing language.")
        breakdown["content_indicators"] += min(spam_score // 2, 25)
        threat_types.add("spam")

    sender_domain = _email_domain(payload.sender)
    sender_name = parseaddr(payload.sender)[0].casefold()
    reply_to = payload.headers.get("reply_to", "")
    reply_domain = _email_domain(reply_to)
    if sender_domain and reply_domain and sender_domain != reply_domain:
        indicators.append(f"Reply-To domain ({reply_domain}) differs from the From domain ({sender_domain}).")
        breakdown["sender_indicators"] += 25
        threat_types.add("sender_mismatch")

    sender_identity = f"{sender_name} {sender_domain}".casefold()
    for brand, official_domains in BRAND_DOMAINS.items():
        if brand in sender_identity and not any(
            sender_domain == domain or sender_domain.endswith(f".{domain}")
            for domain in official_domains
        ):
            indicators.append(f"The sender display name or domain claims to represent {brand.upper()}, but the sender domain is not an official {brand.upper()} domain.")
            breakdown["impersonation_indicators"] += 35
            threat_types.add("brand_impersonation")
            break

    auth_results = payload.headers.get("authentication_results", "")
    if auth_results:
        indicators.append("Authentication-Results header was present; its SPF/DKIM/DMARC claims are reported as supplied and were not independently verified by KESHIHBA.")
    free_mail_domains = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com"}
    if sender_domain in free_mail_domains and any(term in message_text for term in ("microsoft", "paypal", "apple", "bank")):
        indicators.append("The sender domain may not match the brand mentioned in the message.")
        breakdown["impersonation_indicators"] += 25
        threat_types.add("brand_impersonation")

    for url in extracted_urls:
        url_result = analyze_url(URLAnalysisRequest(url=url))
        embedded_url_results.append(url_result)
        intelligence_sources.update(url_result.intelligence_sources)
        threat_types.update(url_result.threat_types)

        if url_result.classification == "Malicious":
            indicators.append(f"Embedded URL was classified as Malicious: {url_result.url}")
            breakdown["url_indicators"] += 35
        elif url_result.classification == "Suspicious":
            indicators.append(f"Embedded URL was classified as Suspicious: {url_result.url}")
            breakdown["url_indicators"] += 20

        if url_result.intelligence_sources:
            indicators.append("A message link matches a current threat-intelligence or reputation source.")
            breakdown["threat_intelligence"] += 70

        for url_indicator in url_result.indicators[:3]:
            indicators.append(f"Embedded URL evidence: {url_indicator}")

    if extracted_urls:
        threat_types.add("suspicious_links") if breakdown["url_indicators"] else None

    model_probability = email_classifier.predict_phishing_probability(combined)
    model_score = round(model_probability * 100) if model_probability is not None else None
    if model_score is not None and model_score >= 85:
        indicators.append(f"The local email classifier returned an elevated uncalibrated score ({model_score}/100).")
        threat_types.add("phishing")
        breakdown["model_indicators"] = 35

    risk_score = min(sum(breakdown.values()), 100)
    if risk_score >= 70:
        classification = "Malicious"
        recommendation = "Do not click links or provide information. Report and delete this email."
    elif risk_score >= 35:
        classification = "Suspicious"
        recommendation = "Verify the sender through an independent channel before taking action."
    elif analysis_warnings:
        classification = "Unknown"
        recommendation = "Some message content could not be analyzed. Review the reported limitations and verify the sender and links independently."
    else:
        classification = "No Known Threat Detected"
        recommendation = "No strong phishing indicators were detected, but remain cautious with unexpected messages."

    explanation = (
        "The score is based on explainable sender, content, URL, and impersonation indicators. "
        "A trained local text model contributes only when its uncalibrated score is at least 85/100. "
        "This is a triage signal, not a guarantee of safety."
    )
    reasons = indicators.copy()
    if spam_score:
        reasons.append(f"Spam score is {spam_score}/100 from promotional or unsolicited-marketing terms.")
    if scam_score:
        reasons.append(f"Scam score is {scam_score}/100 from payment, investment, or recovery-scam terms.")
    if model_score is not None:
        reasons.append(f"Local email model score is {model_score}/100; this score is not calibrated as a probability.")
    if not reasons:
        reasons.append("No strong sender, content, URL, model, or threat-intelligence indicators were found.")

    email_category, category_evidence = _classify_email_category(message_text, payload.subject, extracted_urls)
    security_verdict = _determine_security_verdict(classification, threat_types, email_category)
    threat_assessment = sorted(threat_types)
    return EmailAnalysisResponse(
        classification=classification,
        risk_score=risk_score,
        threat_types=sorted(threat_types),
        spam_score=spam_score,
        scam_score=scam_score,
        model_score=model_score,
        model_used=model_probability is not None,
        model_note=(
            "Local email model was used."
            if model_probability is not None
            else "Local email model is unavailable. Run python scripts/train_email_model.py from backend/."
        ),
        intelligence_sources=sorted(intelligence_sources),
        indicators=indicators,
        reasons=reasons,
        extracted_urls=extracted_urls,
        embedded_url_results=embedded_url_results,
        risk_breakdown=breakdown,
        headers={"from": payload.sender, "subject": payload.subject, **payload.headers},
        explanation=explanation,
        recommendation=recommendation,
        email_category=email_category,
        category_evidence=category_evidence,
        security_verdict=security_verdict,
        threat_assessment=threat_assessment,
        model_probability=model_probability,
        calibrated_probability=None,
        heuristic_risk_score=risk_score,
    )


def analyze_url(payload: URLAnalysisRequest) -> URLAnalysisResponse:
    submitted_url, parsed, warnings = _normalize_url(payload.url)
    normalized_url = submitted_url
    host = ""
    if parsed is not None and parsed.scheme.lower() in {"http", "https"}:
        try:
            normalized_url = _normalize_url(payload.url)[0]
            host = (urlsplit(normalized_url).hostname or "").lower()
        except ValueError:
            warnings.append("URL hostname or port could not be normalized.")
    features = _url_features(normalized_url, parsed)
    indicators: list[str] = []
    local_indicators: list[dict[str, object]] = []
    threat_types: set[str] = set()
    valid_url = bool(parsed and parsed.scheme.lower() in {"http", "https"} and host)
    intelligence_sources = threat_intelligence.lookup(normalized_url) if valid_url else []
    virustotal = None
    google_safe_browsing = None
    if valid_url:
        virustotal = threat_intelligence.lookup_virustotal(normalized_url)
        if not virustotal or virustotal.get("status") in {"disabled", "not_found", "error", "rate_limited"}:
            google_safe_browsing = threat_intelligence.lookup_google_safe_browsing(normalized_url)
    confirmed_malicious = bool(intelligence_sources)
    domain_intelligence = analyze_domain(host) if host else {}
    model_probability = url_classifier.predict_phishing_probability(normalized_url) if valid_url else None
    model_score = round(model_probability * 100) if model_probability is not None else None
    risk_score = 0

    for warning in warnings:
        if "https:// was assumed" in warning:
            continue
        risk_score += _add_indicator(indicators, local_indicators, warning, 30, "validation")

    if parsed is None or urlsplit(normalized_url).scheme not in {"http", "https"} or not host:
        if not warnings:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The URL is malformed or uses an unsupported protocol.",
                30,
                "validation",
            )
    else:
        split = urlsplit(normalized_url)
        if not features["https_present"]:
            risk_score += _add_indicator(indicators, local_indicators, "The URL does not use HTTPS.", 12, "transport")
        if features["has_ip_hostname"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The URL uses an IP address instead of a recognizable domain name.",
                25,
                "host",
            )
        if "@" in split.netloc:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The URL contains user-info before its host, which can disguise the destination.",
                25,
                "host",
            )
        if host.startswith("xn--") or ".xn--" in host:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The hostname uses internationalized punycode that may conceal lookalike characters.",
                20,
                "host",
            )
        if int(features["num_subdomains"]) >= 3:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The hostname has an unusually large number of subdomains.",
                15,
                "host",
            )
        if int(features["hostname_length"]) > 253:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The hostname exceeds the maximum DNS name length.",
                30,
                "validation",
            )
        if int(features["url_length"]) > 120:
            risk_score += _add_indicator(indicators, local_indicators, "The URL is unusually long.", 10, "structure")
        if features["suspicious_encoding"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The URL contains encoded characters that can obscure the destination.",
                12,
                "structure",
            )
        if features["external_redirect_parameter"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "A redirect parameter points to a different external hostname; verify the final destination.",
                12,
                "redirect",
            )
            threat_types.add("external_redirect")
        if features["unusual_delimiters"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The URL contains unusual delimiters often used to mislead readers.",
                12,
                "structure",
            )
        if features["url_shortener"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The URL uses a shortener or does not expose its final destination.",
                18,
                "host",
            )
            threat_types.add("suspicious_shortener")
        if features["misleading_brand_impersonation"]:
            brands = ", ".join(str(brand).upper() for brand in features["impersonated_brands"])
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                f"The hostname appears to impersonate {brands} using an unrelated destination or a lookalike domain.",
                25,
                "impersonation",
            )
            threat_types.add("brand_impersonation")
        if features["unusual_registered_label"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The registered domain label has an unusual run of consonants; this is a weak structural signal, not proof of phishing.",
                15,
                "host",
            )
            threat_types.add("suspicious_domain_structure")
        if features["high_entropy_registered_label"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The registered domain label has unusually high character diversity; this weak structural signal is not proof of phishing.",
                10,
                "host",
            )
            threat_types.add("suspicious_domain_structure")
        if features["digit_heavy_registered_label"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The registered domain label contains an unusual concentration of digits; verify the destination carefully.",
                10,
                "host",
            )
            threat_types.add("suspicious_domain_structure")
        if features["nonstandard_port"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                f"The URL uses nonstandard port {split.port}; confirm that this service is expected.",
                8,
                "transport",
            )
            threat_types.add("unusual_port")
        if features["executable_download"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The URL points directly to a script or executable download; do not run the file unless its source is verified.",
                18,
                "download",
            )
            threat_types.add("suspicious_download")
        if features["suspicious_hostname_patterns"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The hostname contains an account, verification, or payment keyword.",
                10,
                "host",
            )
        elif features["suspicious_path_patterns"]:
            risk_score += _add_indicator(
                indicators,
                local_indicators,
                "The path contains account, verification, or payment language.",
                5,
                "path",
            )

    independent_rule_count = sum(
        1
        for item in local_indicators
        if item.get("category") in {"transport", "structure", "redirect", "host", "path", "download"}
    )
    if valid_url and independent_rule_count >= 3:
        risk_score += _add_indicator(
            indicators,
            local_indicators,
            "Several independent URL structure rules matched; treat this link cautiously. This heuristic is not proof of phishing.",
            10,
            "rule_correlation",
        )
        threat_types.add("suspicious_url_structure")

    for check in domain_intelligence.get("checks", []) if isinstance(domain_intelligence, dict) else []:
        if not isinstance(check, dict):
            continue
        weight = int(check.get("weight", 0) or 0)
        message = str(check.get("message", "")).strip()
        severity = str(check.get("severity", "unknown"))
        if severity == "warning" and weight > 0 and message:
            risk_score += _add_indicator(indicators, local_indicators, message, weight, "domain_intelligence")
            if "domain" in message.lower():
                threat_types.add("new_or_unverified_domain")
            if "mx" in message.lower() or "spf" in message.lower():
                threat_types.add("email_infrastructure_gap")

    if intelligence_sources:
        threat_types.update(
            {"phishing"} if "OpenPhish Community" in intelligence_sources else {"malware_distribution"}
        )
        feed_reason = "The URL matches a current threat-intelligence feed."
        indicators.append(feed_reason)
        local_indicators.append(
            {"category": "threat_intelligence", "weight": 90, "severity": "high", "reason": feed_reason}
        )
        risk_score = max(risk_score, 90)

    if google_safe_browsing and google_safe_browsing.get("status") == "detected":
        confirmed_malicious = True
        intelligence_sources = sorted(set(intelligence_sources) | {"Google Safe Browsing"})
        found_types = google_safe_browsing.get("threat_types", [])
        types = {str(item) for item in found_types} if isinstance(found_types, list) else set()
        threat_types.update({"phishing"} if "SOCIAL_ENGINEERING" in types else set())
        threat_types.update({"malware_distribution"} if "MALWARE" in types else set())
        threat_types.update({"unwanted_software"} if "UNWANTED_SOFTWARE" in types else set())
        threat_types.update({"potentially_harmful_application"} if "POTENTIALLY_HARMFUL_APPLICATION" in types else set())
        if not types:
            threat_types.add("malicious_url")
        reason = "Google Safe Browsing returned a threat match (fresh lookup)."
        indicators.append(reason)
        local_indicators.append({"category": "threat_intelligence", "weight": 95, "severity": "high", "reason": reason})
        risk_score = max(risk_score, 95)

    if virustotal and virustotal.get("status") == "detected":
        malicious_count = int(virustotal.get("malicious", 0) or 0)
        suspicious_count = int(virustotal.get("suspicious", 0) or 0)
        if malicious_count or suspicious_count:
            intelligence_sources = sorted(set(intelligence_sources) | {"VirusTotal"})
            indicators.append(
                f"VirusTotal reports {malicious_count} malicious and {suspicious_count} suspicious detections."
            )
            vt_weight = 90 if malicious_count else 70 if suspicious_count >= 2 else 45
            local_indicators.append(
                {
                    "category": "reputation",
                    "weight": vt_weight,
                    "severity": "high" if vt_weight >= 70 else "medium",
                    "reason": indicators[-1],
                }
            )
        if malicious_count:
            confirmed_malicious = True
            threat_types.add("malware_distribution")
            if "phishing" in virustotal.get("categories", []):
                threat_types.add("phishing")
            risk_score = max(risk_score, 90)
        elif suspicious_count >= 2:
            threat_types.add("suspicious_reputation")
            risk_score = max(risk_score, 70)
        elif suspicious_count == 1:
            threat_types.add("suspicious_reputation")
            risk_score = max(risk_score, 45)

    if virustotal:
        vt_status = virustotal.get("status")
        if vt_status == "detected":
            reputation_status = str(virustotal.get("message") or "VirusTotal reported malicious or suspicious detections.")
        elif vt_status == "clean_or_unknown":
            reputation_status = "VirusTotal returned a report with no malicious or suspicious detections."
        elif vt_status == "not_found":
            reputation_status = "VirusTotal has no report for this URL; treat this as unknown, not safe."
        elif vt_status == "disabled":
            reputation_status = str(virustotal.get("message"))
        elif vt_status == "skipped_sensitive_parameters":
            reputation_status = "Third-party URL reputation lookup was skipped to protect potentially private URL data."
        elif vt_status == "invalid_url":
            reputation_status = "VirusTotal was not checked because the URL is invalid."
        elif vt_status == "rate_limited":
            reputation_status = "VirusTotal rate limit was reached; reputation evidence is unavailable."
        else:
            reputation_status = "VirusTotal lookup failed or timed out; reputation evidence is unavailable."
    else:
        reputation_status = "VirusTotal was not checked because the URL is invalid or could not be normalized."

    model_prediction = None
    model_risk_points = 0
    if model_score is not None:
        model_prediction = "high_score_signal" if model_score >= 85 else "no_high_score_signal"
    local_risk_without_model = risk_score
    model_conflict = model_score is not None and model_score >= 85 and local_risk_without_model < 15 and not intelligence_sources
    if model_score is not None and model_score >= 85 and not model_conflict:
        model_risk_points = 25 if model_score >= 90 else 20
        indicators.append(f"The local URL classifier returned an elevated uncalibrated score ({model_score}/100).")
        local_indicators.append(
            {
                "category": "model",
                "weight": model_risk_points,
                "reason": f"Local URL model score is {model_score}/100 (not calibrated).",
            }
        )
        threat_types.add("phishing")
        risk_score = min(risk_score + model_risk_points, 100)
    elif model_conflict:
        warnings.append(
            "Analysis is inconclusive: the local URL model returned an elevated score, but no independent structural or reputation evidence corroborates it."
        )

    configured_feed_status = threat_intelligence.status().get("feeds", [])
    feed_status = [feed for feed in configured_feed_status if isinstance(feed, dict)]
    openphish_status = next(
        (feed for feed in feed_status if feed.get("name") == "OpenPhish Community"),
        None,
    )
    required_feed_unavailable = bool(
        openphish_status
        and openphish_status.get("enabled")
        and (not openphish_status.get("updated_at") or openphish_status.get("error"))
    )
    for feed in feed_status:
        if not feed.get("enabled"):
            continue
        if feed.get("error"):
            warnings.append(
                f"{feed.get('name', 'Threat feed')} refresh failed ({feed['error']}); the previous snapshot, if any, is retained."
            )
        elif not feed.get("updated_at"):
            warnings.append(
                f"{feed.get('name', 'Threat feed')} has not completed an initial refresh; no-match is inconclusive."
            )

    if model_conflict:
        classification = "Unknown"
        recommendation = "Do not open this link or enter sensitive information until it has been checked with an independent security service."
    elif not valid_url:
        classification = "Unknown"
        recommendation = "This input could not be analyzed as a valid HTTP or HTTPS URL. Do not open it until you can verify the destination."
    elif confirmed_malicious:
        classification = "Malicious"
        recommendation = "Do not open this link. Report it and remove it from the message."
    elif risk_score < 35 and (model_probability is None or required_feed_unavailable):
        classification = "Unknown"
        recommendation = "A critical URL check is unavailable and the available evidence is inconclusive. Verify the destination with an independent security service before opening it."
    elif risk_score >= 70:
        classification = "High Risk"
        recommendation = "Avoid this link. Multiple risk indicators are present, but a confirmed malicious reputation match was not found."
    elif risk_score >= 35:
        classification = "Suspicious"
        recommendation = "Do not enter credentials or payment details until the destination is independently verified."
    else:
        classification = "No Known Threat Detected"
        recommendation = "Available checks found no strong risk indicators. This result does not prove the site is safe; the page itself was not fetched or rendered."

    reasons = indicators.copy()
    if model_score is not None:
        reasons.append(f"Local URL model score is {model_score}/100; this score is not calibrated as a probability.")
    reasons.append(reputation_status)
    if virustotal and virustotal.get("analysis_date"):
        reasons.append(f"VirusTotal last analysis date: {virustotal['analysis_date']}.")
    if virustotal and virustotal.get("total_engines") is not None:
        reasons.append(f"VirusTotal engines in report: {virustotal['total_engines']}.")
    if not indicators and not intelligence_sources and (not virustotal or virustotal.get("status") in {"disabled", "not_found", "clean_or_unknown"}):
        reasons.append("No suspicious structure, feed match, local model signal, or reputation hit was found.")

    threat_intelligence_summary = {
        "feeds": intelligence_sources,
        "feed_status": feed_status,
        "virustotal": virustotal,
        "google_safe_browsing": google_safe_browsing,
        "status": reputation_status,
    }
    feed_checks: dict[str, str] = {}
    for feed in feed_status:
        name = str(feed.get("name", ""))
        check_name = "openphish" if name == "OpenPhish Community" else "urlhaus" if name == "URLhaus Recent" else name.casefold().replace(" ", "_")
        if name in intelligence_sources:
            feed_checks[check_name] = "matched"
        elif not feed.get("enabled"):
            feed_checks[check_name] = "not_checked"
        elif feed.get("error"):
            feed_checks[check_name] = "error"
        elif feed.get("updated_at"):
            feed_checks[check_name] = "no_match"
        else:
            feed_checks[check_name] = "unknown"

    vt_check = (
        "matched"
        if virustotal and virustotal.get("status") == "detected" and (virustotal.get("malicious", 0) or virustotal.get("suspicious", 0))
        else "no_match"
        if virustotal and virustotal.get("status") == "clean_or_unknown"
        else "error"
        if virustotal and virustotal.get("status") in {"error", "rate_limited"}
        else "unknown"
        if virustotal and virustotal.get("status") == "not_found"
        else "not_checked"
    )
    gsb_check = (
        "matched"
        if google_safe_browsing and google_safe_browsing.get("status") == "detected"
        else "no_match"
        if google_safe_browsing and google_safe_browsing.get("status") == "no_match"
        else "error"
        if google_safe_browsing and google_safe_browsing.get("status") in {"error", "rate_limited"}
        else "not_checked"
    )
    intel_provider_states = [*feed_checks.values(), vt_check, gsb_check]
    if "matched" in intel_provider_states:
        intel_check = "matched"
    elif "error" in intel_provider_states and "no_match" in intel_provider_states:
        intel_check = "unknown"
    elif "no_match" in intel_provider_states:
        intel_check = "no_match"
    elif "error" in intel_provider_states:
        intel_check = "error"
    elif "unknown" in intel_provider_states:
        intel_check = "unknown"
    else:
        intel_check = "not_checked"

    dns_status = domain_intelligence.get("dns", {}).get("status") if isinstance(domain_intelligence.get("dns"), dict) else None
    ssl_status = domain_intelligence.get("ssl", {}) if isinstance(domain_intelligence.get("ssl"), dict) else {}
    rdap_status = domain_intelligence.get("rdap", {}) if isinstance(domain_intelligence.get("rdap"), dict) else {}
    ct_status = domain_intelligence.get("certificate_transparency", {}) if isinstance(domain_intelligence.get("certificate_transparency"), dict) else {}
    check_statuses = {
        "url_analysis": "completed" if valid_url else "error",
        "threat_intelligence": intel_check,
        **feed_checks,
        "virustotal": vt_check,
        "google_safe_browsing": gsb_check,
        "dns_analysis": "completed" if dns_status == "checked" else "error" if dns_status in {"partial", "unavailable"} else "unknown",
        "tls_analysis": "completed" if ssl_status.get("checked") else "error" if ssl_status.get("error") else "unknown",
        "domain_registration": "completed" if rdap_status.get("checked") else "error" if rdap_status.get("error") else "unknown",
        "certificate_transparency": "completed" if ct_status.get("checked") else "error" if ct_status.get("error") else "unknown",
        "dns_history": "not_checked",
        "ip_reputation": "not_checked",
        "redirect_analysis": "not_checked",
        "webpage_analysis": "not_checked",
        "ml_model": "completed" if model_probability is not None else "not_checked",
    }
    components = urlsplit(normalized_url) if valid_url else None
    parsed_hostname = (components.hostname or "") if components else ""
    try:
        url_port = components.port if components else None
    except ValueError:
        url_port = None
    url_components: dict[str, object] = {
        "scheme": components.scheme if components else None,
        "hostname": parsed_hostname or None,
        "registered_domain": domain_intelligence.get("registered_domain"),
        "subdomain": (
            parsed_hostname[: -(len(str(domain_intelligence["registered_domain"])) + 1)]
            if parsed_hostname and domain_intelligence.get("registered_domain")
            and parsed_hostname != domain_intelligence.get("registered_domain")
            and parsed_hostname.endswith(f".{domain_intelligence['registered_domain']}")
            else None
        ),
        "ip_address": parsed_hostname if features["has_ip_hostname"] else None,
        "port": url_port,
        "path": components.path if components else None,
        "query": components.query if components else None,
        "url_length": features["url_length"],
        "hostname_length": features["hostname_length"],
        "contains_percent_encoding": features["suspicious_encoding"],
        "uses_punycode": bool(parsed_hostname and ("xn--" in parsed_hostname)),
    }
    limitations = [
        "The webpage was not fetched or rendered; page text, forms, JavaScript navigation, and downloads were not inspected.",
        "The local model score is uncalibrated and is not a probability or confidence estimate.",
        "No known threat match does not establish that the URL is safe.",
        "Registered-domain boundaries use a lightweight suffix heuristic, not a complete Public Suffix List.",
    ]
    if check_statuses["redirect_analysis"] == "not_checked":
        limitations.append("HTTP redirect chains were not followed during this scan. Use the isolated link-expander tool for a separate bounded check.")
    if intel_check in {"error", "unknown", "not_checked"}:
        limitations.append("Threat-intelligence coverage was incomplete or unavailable; check the per-provider statuses and timestamps.")
    limitations.append("Historical DNS changes and automated IP reputation are not checked in this URL scan.")
    category = (
        "possible_phishing"
        if {"phishing", "credential_theft", "brand_impersonation"}.intersection(threat_types)
        else "possible_malware"
        if "malware_distribution" in threat_types
        else "suspicious_url"
        if risk_score >= 35
        else "undetermined"
    )
    risk_level = (
        "unknown"
        if model_conflict
        or not valid_url
        or (risk_score < 35 and (model_probability is None or required_feed_unavailable) and not confirmed_malicious)
        else "malicious"
        if confirmed_malicious
        else "high"
        if risk_score >= 70
        else "suspicious"
        if risk_score >= 35
        else "low"
    )
    return URLAnalysisResponse(
        url=normalized_url,
        submitted_url=payload.url,
        normalized_url=normalized_url,
        hostname=host or None,
        url_components=url_components,
        status=classification,
        risk_level=risk_level,
        category=category,
        confidence=None,
        checks=check_statuses,
        limitations=limitations,
        model_prediction=model_prediction,
        model_probability=model_probability,
        local_indicators=local_indicators,
        threat_intelligence=threat_intelligence_summary,
        domain_intelligence=domain_intelligence,
        warnings=warnings,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        classification=classification,
        risk_score=min(risk_score, 100),
        model_score=model_score,
        model_used=model_probability is not None,
        model_note=(
            "Local URL model was used."
            if model_probability is not None
            else "Local URL model is unavailable. Run python scripts/train_url_model.py from backend/."
        ),
        virustotal=virustotal,
        google_safe_browsing=google_safe_browsing,
        reputation_status=reputation_status,
        threat_types=sorted(threat_types),
        intelligence_sources=intelligence_sources,
        indicators=indicators,
        reasons=reasons,
        explanation="URL checks use transparent structure rules, an uncalibrated local model, public threat feeds, and optional Google Safe Browsing and VirusTotal reputation. No match is not proof of safety; the submitted page is not fetched or rendered.",
        recommendation=recommendation,
    )
