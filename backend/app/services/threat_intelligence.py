import os
import threading
import time
import base64
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

import requests


VIRUSTOTAL_URL_REPORT_URL = "https://www.virustotal.com/api/v3/urls/{url_id}"
VIRUSTOTAL_IP_REPORT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
OPENPHISH_REFRESH_SECONDS = 12 * 60 * 60
URLHAUS_REFRESH_SECONDS = 5 * 60
FAILED_REFRESH_RETRY_SECONDS = 5 * 60
VIRUSTOTAL_CACHE_SECONDS = 30 * 60
VIRUSTOTAL_HEALTH_CACHE_SECONDS = 5 * 60
PROVIDER_TIMEOUT = (1.5, 4)
VIRUSTOTAL_GUI_URL = "https://www.virustotal.com/gui/url/{url_id}"
SENSITIVE_QUERY_PARTS = ("token", "secret", "password", "credential", "session", "signature", "auth", "email", "phone")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.lower(), f"{host}{port}", parsed.path or "/", parsed.query, ""))
    except ValueError:
        return ""


def _virustotal_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _has_sensitive_query(url: str) -> bool:
    if any(
        any(part in key.lower() for part in SENSITIVE_QUERY_PARTS)
        for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    ):
        return True
    # Long opaque path tokens often carry private conversation, session, or reset IDs.
    for segment in unquote(urlsplit(url).path).split("/"):
        if len(segment) >= 24 and any(char.isalpha() for char in segment) and any(char.isdigit() for char in segment):
            if all(char.isalnum() or char in "-_" for char in segment):
                return True
    return False


def _virustotal_api_keys() -> list[str]:
    """Return configured VirusTotal keys in failover order without exposing values."""
    values = [os.getenv("VIRUSTOTAL_API_KEY", "")]
    values.extend(os.getenv("VIRUSTOTAL_API_KEYS", "").split(","))
    placeholders = {"your_virustotal_api_key_here", "your_virustotal_key_here"}
    return list(dict.fromkeys(
        value.strip() for value in values
        if value.strip() and value.strip().casefold() not in placeholders
    ))


def _network_error_detail(error: BaseException) -> str:
    """Describe connection failures without including URLs, keys, or request data."""
    if isinstance(error, requests.exceptions.ProxyError):
        return "Check the configured outbound proxy and its credentials."
    if isinstance(error, requests.exceptions.SSLError):
        return "Check TLS inspection, the system clock, and the trusted CA certificates."
    if isinstance(error, requests.exceptions.ConnectTimeout):
        return "The connection timed out; check outbound firewall and proxy access."
    if isinstance(error, requests.exceptions.ReadTimeout):
        return "The provider did not respond in time; try again later."
    if isinstance(error, requests.exceptions.ConnectionError):
        return "The backend could not establish an outbound connection. Check DNS, firewall, and proxy settings."
    return "Check backend outbound network access and provider configuration."


class ThreatIntelligence:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._feeds: dict[str, dict[str, object]] = {
            "OpenPhish Community": {"urls": set(), "updated_at": None, "attempted_at": None, "error": None},
            "URLhaus Recent": {"urls": set(), "updated_at": None, "attempted_at": None, "error": None},
        }
        self._virustotal_cache: dict[str, dict[str, object]] = {}
        self._virustotal_ip_cache: dict[str, dict[str, object]] = {}
        self._virustotal_error: str | None = None
        self._virustotal_attempted_at: str | None = None
        self._virustotal_connection: dict[str, object] = {"status": "not_checked", "checked_at": None, "error": None}
        self._virustotal_connection_checked_at = 0.0
        self._google_safe_browsing_cache: dict[str, dict[str, object]] = {}
        self._google_safe_browsing_error: str | None = None
        self._google_safe_browsing_attempted_at: str | None = None

    def lookup_google_safe_browsing(self, url: str) -> dict[str, object]:
        canonical = _canonical_url(url)
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        base = {"source": "Google Safe Browsing", "enabled": bool(api_key), "found": False, "cached": False}
        if not canonical:
            return {**base, "status": "invalid_url", "checked_at": None, "message": "The URL is invalid."}
        if _has_sensitive_query(canonical):
            return {**base, "status": "skipped_sensitive_parameters", "checked_at": None,
                    "message": "Lookup skipped because the URL has potentially sensitive query or path data."}
        if not api_key:
            return {**base, "status": "disabled", "checked_at": None,
                    "message": "Google Safe Browsing is not configured. Add GOOGLE_SAFE_BROWSING_API_KEY to the backend."}
        now = time.time()
        with self._lock:
            cached = self._google_safe_browsing_cache.get(canonical)
            if cached and now < float(cached["expires_at"]):
                result = dict(cached["result"])
                result["cached"] = True
                return result
            self._google_safe_browsing_attempted_at = _utc_now()
        checked_at = _utc_now()
        try:
            response = requests.post(
                GOOGLE_SAFE_BROWSING_URL,
                params={"key": api_key},
                json={
                    "client": {"clientId": "kesihba", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": canonical}],
                    },
                },
                timeout=PROVIDER_TIMEOUT,
            )
            if response.status_code in {401, 403}:
                raise PermissionError(f"Google Safe Browsing authentication failed with HTTP {response.status_code}")
            if response.status_code == 429:
                raise RuntimeError("Google Safe Browsing rate limit exceeded")
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Unexpected Google Safe Browsing response format")
            threats = payload.get("matches", [])
            if not isinstance(threats, list):
                raise ValueError("Google Safe Browsing returned invalid threats")
            threat_types = sorted({
                str(value).strip()
                for item in threats if isinstance(item, dict)
                for value in (item.get("threatType", []) if isinstance(item.get("threatType", []), list) else [item.get("threatType")])
                if value
            })
            result = {**base, "enabled": True, "status": "detected" if threat_types else "no_match",
                      "found": bool(threat_types), "checked_at": checked_at, "threat_types": threat_types,
                      "message": ("Google Safe Browsing reports a threat match; accuracy and reliability are not guaranteed." if threat_types else
                                  "Google Safe Browsing returned no match; this does not establish that the URL is safe.")}
            # V4 has no response cache duration; keep positive matches fresh within Google's 30 minute limit.
            ttl = 1800 if threat_types else 300
            with self._lock:
                self._google_safe_browsing_cache[canonical] = {"expires_at": now + ttl, "result": result}
                self._google_safe_browsing_error = None
            return result
        except (requests.RequestException, PermissionError, RuntimeError, ValueError, TypeError, AttributeError) as error:
            with self._lock:
                self._google_safe_browsing_error = type(error).__name__
            detail = _network_error_detail(error) if isinstance(error, requests.RequestException) else "Check the API key and provider quota."
            return {**base, "enabled": True, "status": "rate_limited" if "rate limit" in str(error).lower() else "error",
                    "checked_at": checked_at, "error": type(error).__name__,
                    "message": f"Google Safe Browsing lookup failed ({type(error).__name__}). {detail}"}

    def refresh_due(self) -> None:
        now = time.time()
        with self._lock:
            openphish_due = self._is_due("OpenPhish Community", now, OPENPHISH_REFRESH_SECONDS)
            urlhaus_due = bool(os.getenv("URLHAUS_AUTH_KEY")) and self._is_due(
                "URLhaus Recent", now, URLHAUS_REFRESH_SECONDS
            )

        if openphish_due:
            self._refresh_openphish()
        if urlhaus_due:
            self._refresh_urlhaus()

    def refresh_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            self.refresh_due()
            stop_event.wait(60)

    def lookup(self, url: str) -> list[str]:
        canonical = _canonical_url(url)
        if not canonical:
            return []
        with self._lock:
            return [name for name, feed in self._feeds.items() if canonical in feed["urls"]]

    def lookup_virustotal(self, url: str) -> dict[str, object] | None:
        keys = _virustotal_api_keys()
        if not keys:
            return self._lookup_virustotal_with_key(url, None)
        last_result: dict[str, object] | None = None
        for index, api_key in enumerate(keys, start=1):
            result = self._lookup_virustotal_with_key(url, api_key)
            last_result = result
            if result.get("cached"):
                return result
            if result.get("status") not in {"authentication_error", "rate_limited", "error"}:
                result["key_attempts"] = index
                result["fallback_used"] = index > 1
                canonical = _canonical_url(url)
                with self._lock:
                    cached = self._virustotal_cache.get(canonical)
                    if cached:
                        cached["result"] = dict(result)
                return result
        if last_result is not None:
            last_result["key_attempts"] = len(keys)
            last_result["fallback_used"] = len(keys) > 1
        return last_result

    def check_virustotal_connection(self) -> dict[str, object]:
        """Check provider reachability separately from whether a key is configured."""
        api_keys = _virustotal_api_keys()
        if not api_keys:
            result = {"status": "not_configured", "checked_at": None, "error": None}
            with self._lock:
                self._virustotal_connection = result
                self._virustotal_connection_checked_at = time.time()
            return dict(result)
        now = time.time()
        with self._lock:
            if now - self._virustotal_connection_checked_at < VIRUSTOTAL_HEALTH_CACHE_SECONDS:
                return dict(self._virustotal_connection)
        checked_at = _utc_now()
        result: dict[str, object] = {"status": "error", "checked_at": checked_at, "error": None}
        for api_key in api_keys:
            try:
                # example.com is public and non-sensitive; this checks API auth and connectivity.
                response = requests.get(
                    VIRUSTOTAL_URL_REPORT_URL.format(url_id=_virustotal_url_id("https://example.com/")),
                    headers={"x-apikey": api_key},
                    timeout=PROVIDER_TIMEOUT,
                )
                if response.status_code in {200, 404}:
                    result = {"status": "connected", "checked_at": checked_at, "error": None}
                    break
                if response.status_code in {401, 403}:
                    result = {"status": "authentication_error", "checked_at": checked_at, "error": f"HTTP {response.status_code}"}
                    continue
                if response.status_code == 429:
                    result = {"status": "rate_limited", "checked_at": checked_at, "error": "HTTP 429"}
                    continue
                result = {"status": "error", "checked_at": checked_at, "error": f"HTTP {response.status_code}"}
                break
            except requests.RequestException as error:
                result = {"status": "unreachable", "checked_at": checked_at, "error": type(error).__name__,
                          "message": _network_error_detail(error)}
                break
        with self._lock:
            self._virustotal_connection = result
            self._virustotal_connection_checked_at = now
        return dict(result)

    def _lookup_virustotal_with_key(self, url: str, api_key: str | None) -> dict[str, object]:
        canonical = _canonical_url(url)
        if not canonical:
            return {
                "source": "VirusTotal",
                "status": "invalid_url",
                "found": False,
                "enabled": bool(api_key),
                "checked_at": None,
                "cached": False,
                "error": "invalid_url",
                "message": "VirusTotal was not checked because the URL is invalid.",
            }
        if _has_sensitive_query(canonical):
            return {
                "source": "VirusTotal",
                "status": "skipped_sensitive_parameters",
                "found": False,
                "enabled": bool(api_key),
                "checked_at": None,
                "cached": False,
                "error": None,
                "message": "VirusTotal lookup was skipped because the URL contains potentially sensitive query or path data.",
            }
        if not api_key:
            return {
                "source": "VirusTotal",
                "status": "disabled",
                "found": False,
                "enabled": False,
                "checked_at": None,
                "cached": False,
                "error": None,
                "message": "VirusTotal is not configured. Add VIRUSTOTAL_API_KEY on the backend to enable reputation checks.",
            }

        now = time.time()
        with self._lock:
            cached = self._virustotal_cache.get(canonical)
            if cached and now - float(cached["cached_at"]) < VIRUSTOTAL_CACHE_SECONDS:
                result = dict(cached["result"])
                result["cached"] = True
                return result
            self._virustotal_attempted_at = _utc_now()

        url_id = _virustotal_url_id(canonical)
        checked_at = _utc_now()
        try:
            response = requests.get(
                VIRUSTOTAL_URL_REPORT_URL.format(url_id=url_id),
                headers={"x-apikey": api_key},
                timeout=PROVIDER_TIMEOUT,
            )
            if response.status_code == 404:
                result = {
                    "source": "VirusTotal",
                    "status": "not_found",
                    "found": False,
                    "enabled": True,
                    "checked_at": checked_at,
                    "cached": False,
                    "error": None,
                    "message": "VirusTotal has no report for this URL. This is unknown, not proof of safety.",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "timeout": 0,
                    "total_engines": 0,
                    "categories": [],
                    "analysis_date": None,
                    "last_final_url": None,
                    "gui_url": VIRUSTOTAL_GUI_URL.format(url_id=url_id),
                }
            else:
                if response.status_code in {401, 403}:
                    raise PermissionError(f"VirusTotal authentication failed with HTTP {response.status_code}")
                if response.status_code == 429:
                    raise RuntimeError("VirusTotal rate limit exceeded")
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("Unexpected VirusTotal response format")
                data = payload.get("data")
                if not isinstance(data, dict):
                    raise ValueError("VirusTotal response missing data payload")
                attributes = data.get("attributes")
                if not isinstance(attributes, dict):
                    raise ValueError("VirusTotal response missing attributes")
                stats = attributes.get("last_analysis_stats", {})
                if not isinstance(stats, dict):
                    stats = {}
                raw_results = attributes.get("last_analysis_results", {})
                if not isinstance(raw_results, dict):
                    raw_results = {}
                malicious = int(stats.get("malicious", 0) or 0)
                suspicious = int(stats.get("suspicious", 0) or 0)
                harmless = int(stats.get("harmless", 0) or 0)
                undetected = int(stats.get("undetected", 0) or 0)
                timeout = int(stats.get("timeout", 0) or 0)
                categories = sorted(
                    {
                        str(result.get("category", "")).lower()
                        for result in raw_results.values()
                        if isinstance(result, dict) and result.get("category")
                    }
                )
                vendor_results = [
                    {
                        "engine": str(engine),
                        "category": str(result.get("category") or "unknown"),
                        "result": str(result.get("result") or ""),
                    }
                    for engine, result in raw_results.items()
                    if isinstance(result, dict)
                    and result.get("category") in {"malicious", "suspicious"}
                ][:20]
                if malicious or suspicious:
                    status = "detected"
                    message = (
                        f"VirusTotal reports {malicious} malicious and {suspicious} suspicious engine detections."
                    )
                else:
                    status = "clean_or_unknown"
                    message = "VirusTotal returned a report with no malicious or suspicious engine detections."
                analysis_date = attributes.get("last_analysis_date")
                if isinstance(analysis_date, int):
                    analysis_date = datetime.fromtimestamp(analysis_date, timezone.utc).isoformat()
                elif analysis_date is not None:
                    analysis_date = str(analysis_date)
                result = {
                    "source": "VirusTotal",
                    "status": status,
                    "found": True,
                    "enabled": True,
                    "checked_at": checked_at,
                    "cached": False,
                    "error": None,
                    "message": message,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": timeout,
                    "total_engines": malicious + suspicious + harmless + undetected + timeout,
                    "categories": categories,
                    "vendor_results": vendor_results,
                    "analysis_date": analysis_date,
                    "last_final_url": attributes.get("last_final_url") or canonical,
                    "gui_url": VIRUSTOTAL_GUI_URL.format(url_id=url_id),
                }
            with self._lock:
                self._virustotal_cache[canonical] = {"cached_at": now, "result": result}
                self._virustotal_error = None
            return result
        except (requests.RequestException, PermissionError, RuntimeError, ValueError, TypeError, AttributeError) as error:
            status = (
                "authentication_error" if isinstance(error, PermissionError)
                else "rate_limited" if "rate limit" in str(error).lower()
                else "error"
            )
            with self._lock:
                self._virustotal_error = type(error).__name__
            detail = _network_error_detail(error) if isinstance(error, requests.RequestException) else "Check the API key and provider quota."
            return {
                "source": "VirusTotal",
                "status": status,
                "found": False,
                "enabled": True,
                "checked_at": checked_at,
                "cached": False,
                "error": type(error).__name__,
                "message": f"VirusTotal lookup failed ({type(error).__name__}). {detail}",
                "gui_url": VIRUSTOTAL_GUI_URL.format(url_id=url_id),
            }

    def lookup_ip_virustotal(self, address: str) -> dict[str, object]:
            try:
                normalized = str(ipaddress.ip_address(address))
            except ValueError:
                return {
                    "source": "VirusTotal",
                    "status": "invalid_ip",
                    "enabled": bool(_virustotal_api_keys()),
                    "error": "invalid_ip",
                }
            api_key = next(iter(_virustotal_api_keys()), None)
            if not api_key:
                return {
                    "source": "VirusTotal",
                    "status": "disabled",
                    "enabled": False,
                    "message": "IP reputation checks require VIRUSTOTAL_API_KEY on the backend.",
                }
            now = time.time()
            with self._lock:
                cached = self._virustotal_ip_cache.get(normalized)
                if cached and now - float(cached["cached_at"]) < VIRUSTOTAL_CACHE_SECONDS:
                    result = dict(cached["result"])
                    result["cached"] = True
                    return result
            try:
                response = requests.get(
                    VIRUSTOTAL_IP_REPORT_URL.format(ip=normalized),
                    headers={"x-apikey": api_key},
                    timeout=PROVIDER_TIMEOUT,
                )
                if response.status_code == 404:
                    result: dict[str, object] = {
                        "source": "VirusTotal",
                        "status": "not_found",
                        "enabled": True,
                        "found": False,
                        "checked_at": _utc_now(),
                        "cached": False,
                        "message": "VirusTotal has no report for this IP address; this is unknown, not proof of safety.",
                    }
                else:
                    if response.status_code in {401, 403}:
                        raise PermissionError(f"VirusTotal authentication failed with HTTP {response.status_code}")
                    if response.status_code == 429:
                        raise RuntimeError("VirusTotal rate limit exceeded")
                    response.raise_for_status()
                    payload = response.json()
                    attributes = payload.get("data", {}).get("attributes", {}) if isinstance(payload, dict) else {}
                    stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes, dict) else {}
                    if not isinstance(stats, dict):
                        raise ValueError("VirusTotal IP response has invalid analysis statistics")
                    malicious = int(stats.get("malicious", 0) or 0)
                    suspicious = int(stats.get("suspicious", 0) or 0)
                    result = {
                        "source": "VirusTotal",
                        "status": "detected" if malicious or suspicious else "clean_or_unknown",
                        "enabled": True,
                        "found": True,
                        "checked_at": _utc_now(),
                        "cached": False,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": int(stats.get("harmless", 0) or 0),
                        "undetected": int(stats.get("undetected", 0) or 0),
                        "message": (
                            f"VirusTotal reports {malicious} malicious and {suspicious} suspicious detections."
                            if malicious or suspicious
                            else "VirusTotal returned no malicious or suspicious IP detections; that is not a guarantee of safety."
                        ),
                    }
                with self._lock:
                    self._virustotal_ip_cache[normalized] = {"cached_at": now, "result": result}
                return result
            except (requests.RequestException, PermissionError, RuntimeError, ValueError, TypeError, AttributeError) as error:
                return {
                    "source": "VirusTotal",
                    "status": "rate_limited" if "rate limit" in str(error).lower() else "error",
                    "enabled": True,
                    "error": type(error).__name__,
                    "message": f"VirusTotal IP lookup failed: {type(error).__name__}.",
                }

    def status(self) -> dict[str, object]:
        with self._lock:
            return {
                "feeds": [
                    {
                        "name": name,
                        "enabled": name != "URLhaus Recent" or bool(os.getenv("URLHAUS_AUTH_KEY")),
                        "entries": len(feed["urls"]),
                        "updated_at": feed["updated_at"],
                        "last_attempt_at": feed["attempted_at"],
                        "error": feed["error"],
                    }
                    for name, feed in self._feeds.items()
                ],
                "virustotal": {
                    "enabled": bool(_virustotal_api_keys()),
                    "configured_key_count": len(_virustotal_api_keys()),
                    # Status must remain local and fast; live provider checks run during scans.
                    "connection": dict(self._virustotal_connection),
                    "cached_entries": len(self._virustotal_cache) + len(self._virustotal_ip_cache),
                    "cache_ttl_seconds": VIRUSTOTAL_CACHE_SECONDS,
                    "last_attempt_at": self._virustotal_attempted_at,
                    "error": self._virustotal_error,
                },
                "google_safe_browsing": {
                    "enabled": bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")),
                    "cached_entries": len(self._google_safe_browsing_cache),
                    "cache_ttl_seconds": 1800,
                    "last_attempt_at": self._google_safe_browsing_attempted_at,
                    "error": self._google_safe_browsing_error,
                    "commercial_use_note": "Google Safe Browsing API v4 is for non-commercial use; use Web Risk for commercial products.",
                },
            }

    def _is_due(self, name: str, now: float, interval: int) -> bool:
        feed = self._feeds[name]
        attempted_at = feed["attempted_at"]
        if attempted_at is None:
            return True
        refreshed = datetime.fromisoformat(str(attempted_at)).timestamp()
        retry_interval = FAILED_REFRESH_RETRY_SECONDS if feed["error"] else interval
        return now - refreshed >= retry_interval

    def _refresh_openphish(self) -> None:
        try:
            response = requests.get(OPENPHISH_URL, timeout=(3, 10))
            response.raise_for_status()
            urls = {
                normalized
                for line in response.text.splitlines()
                if (normalized := _canonical_url(line))
            }
            self._replace_feed("OpenPhish Community", urls)
        except requests.RequestException as error:
            self._set_error("OpenPhish Community", type(error).__name__)

    def _refresh_urlhaus(self) -> None:
        try:
            response = requests.get(
                URLHAUS_RECENT_URL,
                headers={"Auth-Key": os.environ["URLHAUS_AUTH_KEY"]},
                timeout=(3, 10),
            )
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Unexpected URLhaus response format")
            urls = {
                normalized
                for item in data.get("urls", [])
                if isinstance(item, dict)
                and (normalized := _canonical_url(str(item.get("url", ""))))
            }
            self._replace_feed("URLhaus Recent", urls)
        except (requests.RequestException, ValueError, TypeError, AttributeError, KeyError) as error:
            self._set_error("URLhaus Recent", type(error).__name__)

    def _replace_feed(self, name: str, urls: set[str]) -> None:
        with self._lock:
            self._feeds[name] = {
                "urls": urls,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "attempted_at": datetime.now(timezone.utc).isoformat(),
                "error": None,
            }

    def _set_error(self, name: str, error: str) -> None:
        with self._lock:
            self._feeds[name]["attempted_at"] = datetime.now(timezone.utc).isoformat()
            self._feeds[name]["error"] = error


threat_intelligence = ThreatIntelligence()
