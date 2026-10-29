import ipaddress
import http.client
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit

import requests


RDAP_URL = "https://rdap.org/domain/{domain}"
CT_URL = "https://crt.sh/"
DNS_TIMEOUT_SECONDS = 3
NETWORK_TIMEOUT = (1.5, 4)
SYSTEM_DNS_TIMEOUT_SECONDS = 3
DNS_QUERY_URL = "https://cloudflare-dns.com/dns-query"
DNS_RECORD_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "TXT": 16}
IP_GEO_URL = "https://ipwho.is/{address}"
SENSITIVE_QUERY_KEYS = {
    "access_token", "auth", "authorization", "code", "credential", "email",
    "key", "password", "phone", "secret", "session", "signature", "token",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _registered_domain(hostname: str) -> str:
    labels = [label for label in hostname.lower().strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    common_second_level = {"co", "com", "net", "org", "gov", "ac", "edu"}
    if len(labels[-1]) == 2 and labels[-2] in common_second_level and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def normalize_hostname(hostname: str) -> str:
    candidate = hostname.strip().rstrip(".")
    try:
        address = ipaddress.ip_address(candidate)
        return str(address)
    except ValueError:
        pass
    normalized = candidate.encode("idna").decode("ascii").lower()
    labels = normalized.split(".")
    if (
        len(normalized) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise ValueError("The hostname is malformed.")
    return normalized


def _contains_sensitive_query(url: str) -> bool:
    try:
        return any(
            key.lower() in SENSITIVE_QUERY_KEYS or any(part in key.lower() for part in ("token", "secret", "password"))
            for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        )
    except ValueError:
        return False


def _resolve_public_addresses(hostname: str) -> list[str]:
    try:
        ip = ipaddress.ip_address(hostname)
        return [str(ip)] if ip.is_global else []
    except ValueError:
        if not hostname or "." not in hostname or hostname.endswith(".local"):
            return []
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(socket.getaddrinfo, hostname, None, type=socket.SOCK_STREAM)
    try:
        records = future.result(timeout=SYSTEM_DNS_TIMEOUT_SECONDS)
    except (OSError, FutureTimeoutError):
        future.cancel()
        return []
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        return []
    return addresses


def _ip_geolocation(addresses: list[str]) -> dict[str, object]:
    """Return approximate public-IP metadata; never query private/reserved IPs."""
    results: list[dict[str, object]] = []
    for address in addresses[:3]:
        try:
            if not ipaddress.ip_address(address).is_global:
                continue
            response = requests.get(IP_GEO_URL.format(address=address), timeout=NETWORK_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict) or data.get("success") is not True:
                continue
            connection = data.get("connection") or {}
            results.append({key: data.get(key) for key in ("country", "region", "city", "latitude", "longitude", "timezone") if data.get(key) is not None} | {
                "ip": address,
                "isp": connection.get("isp"),
                "organization": connection.get("org"),
                "asn": connection.get("asn"),
            })
        except (requests.RequestException, ValueError, TypeError):
            continue
    return {"status": "available" if results else "unavailable", "results": results,
            "note": "Approximate IP registration location; it may identify an ISP, VPN, proxy, or hosting provider rather than a person's location."}


def _dns_records(record_type: str, domain: str) -> dict[str, object]:
    try:
        response = requests.get(
            DNS_QUERY_URL,
            params={"name": domain, "type": DNS_RECORD_TYPES[record_type]},
            headers={"Accept": "application/dns-json"},
            timeout=(1.5, DNS_TIMEOUT_SECONDS),
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("DNS-over-HTTPS response was not an object")
        answers = payload.get("Answer", [])
        values = [
            str(answer["data"]).strip('"')
            for answer in answers
            if isinstance(answer, dict) and answer.get("type") == DNS_RECORD_TYPES[record_type]
        ] if isinstance(answers, list) else []
        return {"status": "checked", "values": values, "error": None}
    except (requests.RequestException, ValueError, KeyError) as error:
        return {"status": "unavailable", "values": [], "error": type(error).__name__}


def _dns_report(domain: str) -> dict[str, object]:
    executor = ThreadPoolExecutor(max_workers=len(DNS_RECORD_TYPES))
    futures = {record_type: executor.submit(_dns_records, record_type, domain) for record_type in DNS_RECORD_TYPES}
    results: dict[str, dict[str, object]] = {}
    for record_type, future in futures.items():
        try:
            results[record_type] = future.result(timeout=DNS_TIMEOUT_SECONDS + 1)
        except FutureTimeoutError:
            future.cancel()
            results[record_type] = {"status": "unavailable", "values": [], "error": "TimeoutError"}
    executor.shutdown(wait=False, cancel_futures=True)
    records = {record_type: result["values"] for record_type, result in results.items()}
    record_status = {record_type: result["status"] for record_type, result in results.items()}
    statuses = [str(result["status"]) for result in results.values()]
    errors = {
        record_type: result["error"]
        for record_type, result in results.items()
        if result["error"]
    }
    txt_records = [str(value) for value in records["TXT"]]
    mx_found = bool(records["MX"])
    spf_found = any("v=spf1" in value.lower() for value in txt_records)
    return {
        "records": records,
        "record_status": record_status,
        "mx_found": mx_found,
        "spf_found": spf_found,
        "txt_found": bool(txt_records),
        "status": "checked" if all(status == "checked" for status in statuses) else "partial" if any(status == "checked" for status in statuses) else "unavailable",
        "errors": errors,
    }


def _ssl_report(hostname: str, addresses: list[str]) -> dict[str, object]:
    report: dict[str, object] = {
        "checked": False,
        "valid": False,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "certificate_age_days": None,
        "error": None,
    }
    try:
        context = ssl.create_default_context()
        last_error: OSError | ssl.SSLError | None = None
        cert: dict[str, Any] | None = None
        for address in addresses:
            try:
                with socket.create_connection((address, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as tls:
                        cert = tls.getpeercert()
                break
            except (OSError, ssl.SSLError) as error:
                last_error = error
        if cert is None:
            if last_error:
                raise last_error
            raise OSError("No public address was available for TLS inspection")
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer_parts = cert.get("issuer", ())
        issuer = ", ".join(
            f"{key}={value}"
            for group in issuer_parts
            for key, value in group
            if key.lower() in {"organizationname", "commonname"}
        )
        now = _utc_now()
        report.update(
            {
                "checked": True,
                "valid": not_before <= now <= not_after,
                "issuer": issuer or None,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "certificate_age_days": max((now - not_before).days, 0),
            }
        )
    except ssl.SSLCertVerificationError as error:
        report["checked"] = True
        report["error"] = type(error).__name__
    except (OSError, ssl.SSLError, ValueError, KeyError, TypeError) as error:
        report["error"] = type(error).__name__
    return report


def _rdap_report(domain: str) -> dict[str, object]:
    report: dict[str, object] = {
        "checked": False,
        "domain_age_days": None,
        "created_at": None,
        "registrar": None,
        "registrant_public": False,
        "error": None,
    }
    try:
        response = requests.get(RDAP_URL.format(domain=domain), timeout=NETWORK_TIMEOUT)
        if response.status_code == 404:
            report["error"] = "not_found"
            return report
        response.raise_for_status()
        data = response.json()
        events = data.get("events", []) if isinstance(data, dict) else []
        created_at = None
        for event in events:
            if isinstance(event, dict) and event.get("eventAction") in {"registration", "registered"}:
                created_at = str(event.get("eventDate") or "")
                break
        if created_at:
            created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            report["created_at"] = created_dt.isoformat()
            report["domain_age_days"] = max((_utc_now() - created_dt).days, 0)
        entities = data.get("entities", []) if isinstance(data, dict) else []
        registrar = None
        registrant_public = False
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles", [])
            if "registrar" in roles and not registrar:
                registrar = _entity_name(entity)
            if "registrant" in roles and _entity_name(entity):
                registrant_public = True
        report.update(
            {
                "checked": True,
                "registrar": registrar,
                "registrant_public": registrant_public,
            }
        )
    except (requests.RequestException, ValueError, TypeError, AttributeError) as error:
        report["error"] = type(error).__name__
    return report


def _entity_name(entity: dict[str, object]) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for field in vcard[1]:
        if isinstance(field, list) and len(field) >= 4 and field[0] in {"fn", "org"}:
            value = field[3]
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _ct_report(domain: str) -> dict[str, object]:
    report: dict[str, object] = {"checked": False, "first_seen": None, "first_seen_age_days": None, "error": None}
    try:
        response = requests.get(
            CT_URL,
            params={"q": domain, "output": "json"},
            timeout=NETWORK_TIMEOUT,
            headers={"User-Agent": "KESHIHBA local URL scanner"},
        )
        response.raise_for_status()
        entries = response.json()
        dates = []
        if isinstance(entries, list):
            for item in entries:
                if isinstance(item, dict) and isinstance(item.get("not_before"), str):
                    try:
                        dates.append(datetime.fromisoformat(item["not_before"].replace("Z", "+00:00")))
                    except ValueError:
                        pass
        if dates:
            first_seen = min(dates)
            report["first_seen"] = first_seen.isoformat()
            report["first_seen_age_days"] = max((_utc_now() - first_seen).days, 0)
        report["checked"] = True
    except (requests.RequestException, ValueError, TypeError, AttributeError) as error:
        report["error"] = type(error).__name__
    return report


def analyze_domain(hostname: str) -> dict[str, object]:
    domain = _registered_domain(hostname)
    report: dict[str, object] = {
        "hostname": hostname,
        "registered_domain": domain,
        "status": "checked",
        "public_addresses": [],
        "checks": [],
        "dns": {},
        "ssl": {},
        "rdap": {},
        "certificate_transparency": {},
        "warnings": [],
    }
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        report["status"] = "not_applicable"
        report["warnings"].append("Domain registration and DNS-record checks do not apply to IP-address hosts.")
        if ipaddress.ip_address(hostname).is_global:
            report["public_addresses"] = [hostname]
            report["ip_geolocation"] = _ip_geolocation([hostname])
        else:
            report["ip_geolocation"] = {
                "status": "not_applicable",
                "results": [],
                "note": "Network ownership and location lookup is limited to public IP addresses.",
            }
        return report

    addresses = _resolve_public_addresses(hostname)
    if not addresses:
        report["status"] = "skipped"
        report["warnings"].append(
            "Domain intelligence skipped because the host did not resolve exclusively to public IP addresses."
        )
        return report

    executor = ThreadPoolExecutor(max_workers=4)
    futures = {
        "dns": executor.submit(_dns_report, domain),
        "ssl": executor.submit(_ssl_report, hostname, addresses),
        "rdap": executor.submit(_rdap_report, domain),
        "ct": executor.submit(_ct_report, domain),
    }
    reports: dict[str, dict[str, object]] = {}
    for name, future in futures.items():
        try:
            reports[name] = future.result(timeout=NETWORK_TIMEOUT[0] + NETWORK_TIMEOUT[1] + 2)
        except FutureTimeoutError:
            future.cancel()
            reports[name] = {"error": "TimeoutError", "checked": False}
    executor.shutdown(wait=False, cancel_futures=True)
    dns = reports["dns"]
    ssl_report = reports["ssl"]
    rdap = reports["rdap"]
    ct = reports["ct"]
    report.update({"dns": dns, "ssl": ssl_report, "rdap": rdap, "certificate_transparency": ct})
    report["public_addresses"] = addresses
    report["ip_geolocation"] = _ip_geolocation(addresses)

    checks: list[dict[str, object]] = []
    domain_age = rdap.get("domain_age_days")
    if isinstance(domain_age, int):
        if domain_age < 30:
            checks.append({"severity": "warning", "weight": 35, "message": f"Very new domain ({domain_age} days old). Treat unexpected login and payment pages with caution."})
        elif domain_age < 90:
            checks.append({"severity": "warning", "weight": 20, "message": f"New domain ({domain_age} days old)."})
        else:
            checks.append({"severity": "pass", "weight": 0, "message": f"Established domain age ({domain_age} days old)."})
    else:
        checks.append({"severity": "unknown", "weight": 0, "message": "Domain registration age unavailable."})

    cert_age = ssl_report.get("certificate_age_days")
    if ssl_report.get("valid"):
        checks.append({"severity": "pass", "weight": 0, "message": "Valid SSL certificate."})
        if isinstance(cert_age, int) and cert_age < 7:
            checks.append({"severity": "warning", "weight": 12, "message": f"SSL certificate issued only {cert_age} days ago."})
    elif ssl_report.get("checked"):
        checks.append({"severity": "warning", "weight": 18, "message": "SSL certificate is not currently valid."})
    else:
        checks.append({"severity": "unknown", "weight": 0, "message": "SSL certificate could not be checked."})

    record_status = dns.get("record_status", {})
    if isinstance(record_status, dict) and record_status.get("MX") == "checked":
        if dns.get("mx_found"):
            checks.append({"severity": "pass", "weight": 0, "message": "MX email records found."})
        else:
            checks.append({"severity": "info", "weight": 0, "message": "No MX email records found; this is not evidence that a website is malicious."})
    else:
        checks.append({"severity": "unknown", "weight": 0, "message": "MX-record check unavailable."})
    if isinstance(record_status, dict) and record_status.get("TXT") == "checked":
        if dns.get("spf_found"):
            checks.append({"severity": "pass", "weight": 0, "message": "SPF email policy found."})
        else:
            checks.append({"severity": "info", "weight": 0, "message": "No SPF email policy found; this is not evidence that a website is malicious."})
    else:
        checks.append({"severity": "unknown", "weight": 0, "message": "SPF-record check unavailable."})

    registrar = rdap.get("registrar")
    if registrar:
        checks.append({"severity": "pass", "weight": 0, "message": f"Registrar: {registrar}."})
    if rdap.get("registrant_public"):
        checks.append({"severity": "pass", "weight": 0, "message": "Public registrant info available."})
    else:
        checks.append({"severity": "unknown", "weight": 0, "message": "Public registrant info unavailable or privacy-protected."})

    if ct.get("first_seen_age_days") is None and ct.get("error"):
        checks.append({"severity": "unknown", "weight": 0, "message": "Certificate Transparency query unavailable or timed out."})

    report["checks"] = checks
    return report


def lookup_dns(hostname: str) -> dict[str, object]:
    normalized = normalize_hostname(hostname)
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        return {"hostname": normalized, "status": "not_applicable", "records": {}, "error": "DNS record lookups require a domain name."}
    addresses = _resolve_public_addresses(normalized)
    if not addresses:
        return {
            "hostname": normalized,
            "status": "unavailable",
            "records": {},
            "error": "Host did not resolve exclusively to public IP addresses.",
        }
    return {"hostname": normalized, **_dns_report(_registered_domain(normalized))}


def check_ssl(hostname: str) -> dict[str, object]:
    normalized = normalize_hostname(hostname)
    addresses = _resolve_public_addresses(normalized)
    if not addresses:
        return {
            "hostname": normalized,
            "checked": False,
            "valid": False,
            "error": "Host did not resolve exclusively to public IP addresses.",
        }
    return {"hostname": normalized, **_ssl_report(normalized, addresses)}


def lookup_domain_age(hostname: str) -> dict[str, object]:
    normalized = normalize_hostname(hostname)
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        return {"hostname": normalized, "checked": False, "error": "Domain age does not apply to IP addresses."}
    addresses = _resolve_public_addresses(normalized)
    if not addresses:
        return {
            "hostname": normalized,
            "checked": False,
            "error": "Host did not resolve exclusively to public IP addresses.",
        }
    return {"hostname": normalized, **_rdap_report(_registered_domain(normalized))}


def expand_public_link(url: str, max_redirects: int = 5) -> dict[str, object]:
    original = url.strip()
    chain: list[dict[str, object]] = []
    if _contains_sensitive_query(original):
        return {
            "status": "skipped",
            "original_url": original,
            "final_url": None,
            "redirects": chain,
            "error": "Sensitive query parameters were detected; link expansion was not attempted.",
        }
    if not 1 <= max_redirects <= 5:
        raise ValueError("The redirect limit must be between 1 and 5.")

    current = original
    for _ in range(max_redirects + 1):
        try:
            parsed = urlsplit(current)
        except ValueError:
            return {
                "status": "blocked",
                "original_url": original,
                "final_url": None,
                "redirects": chain,
                "error": "The submitted or redirected URL is malformed.",
            }
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return {
                "status": "blocked",
                "original_url": original,
                "final_url": None,
                "redirects": chain,
                "error": "Only credential-free HTTP and HTTPS links can be expanded.",
            }
        try:
            hostname = normalize_hostname(parsed.hostname)
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError as error:
            return {
                "status": "blocked",
                "original_url": original,
                "final_url": None,
                "redirects": chain,
                "error": str(error),
            }
        addresses = _resolve_public_addresses(hostname)
        if not addresses:
            return {
                "status": "blocked",
                "original_url": original,
                "final_url": None,
                "redirects": chain,
                "error": "A redirect target did not resolve exclusively to public IP addresses.",
            }
        path = quote(urlunsplit(("", "", parsed.path or "/", parsed.query, "")), safe="/%?:=&+$,;~!*'()@")
        netloc = f"[{hostname}]" if ":" in hostname else hostname
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        if port != default_port:
            netloc = f"{netloc}:{port}"
        normalized = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
        if _contains_sensitive_query(normalized):
            return {
                "status": "skipped",
                "original_url": original,
                "final_url": None,
                "redirects": chain,
                "error": "A redirect contains sensitive query parameters; expansion stopped.",
            }
        last_error: Exception | None = None
        status_code: int | None = None
        location: str | None = None
        for address in addresses:
            try:
                with socket.create_connection((address, port), timeout=4) as raw_socket:
                    if parsed.scheme.lower() == "https":
                        context = ssl.create_default_context()
                        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                            tls_socket.sendall(
                                f"HEAD {path} HTTP/1.1\r\nHost: {netloc}\r\nUser-Agent: KESHIHBA-Link-Inspector/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode("ascii")
                            )
                            response = http.client.HTTPResponse(tls_socket)
                            response.begin()
                            status_code = response.status
                            location = response.getheader("Location")
                            response.close()
                    else:
                        raw_socket.sendall(
                            f"HEAD {path} HTTP/1.1\r\nHost: {netloc}\r\nUser-Agent: KESHIHBA-Link-Inspector/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode("ascii")
                        )
                        response = http.client.HTTPResponse(raw_socket)
                        response.begin()
                        status_code = response.status
                        location = response.getheader("Location")
                        response.close()
                break
            except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeError) as error:
                last_error = error
        if status_code is None:
            return {
                "status": "unavailable",
                "original_url": original,
                "final_url": None,
                "redirects": chain,
                "error": type(last_error).__name__ if last_error else "ConnectionError",
            }
        redirect = {"url": normalized, "status_code": status_code, "location": location}
        chain.append(redirect)
        if status_code not in {301, 302, 303, 307, 308} or not location:
            final_url = normalized
            return {
                "status": "expanded",
                "original_url": original,
                "final_url": final_url,
                "redirects": chain,
                "error": None if status_code < 400 else f"Target returned HTTP {status_code}.",
            }
        current = urljoin(normalized, location)

    return {
        "status": "redirect_limit",
        "original_url": original,
        "final_url": None,
        "redirects": chain,
        "error": f"Redirect chain exceeded the maximum of {max_redirects} hops.",
    }
