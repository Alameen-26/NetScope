"""HTTP check: does a website answer, how fast, and is its certificate healthy?

We use ``http.client`` from the standard library (not ``requests``) so every
step is visible: open a connection, send the request, read the status line
and headers, then read the body to time the full response.

For ``https://`` URLs the connection is wrapped in TLS. Python checks the
certificate against the system's trusted authorities by default; afterwards
we read the certificate's expiry date ("notAfter") and work out how many days
are left. Expired or soon-to-expire certificates are a classic cause of
"the site suddenly stopped working".

When verification fails, Python refuses the connection. To still show the
user *which* certificate was sent (and when it expired), we connect a second
time without verifying, read only the certificate, and hang up - no request
is sent over that unchecked connection. Anything learned that way is marked
"unverified".

Redirects are followed only to http:// and https:// addresses with a valid
host and port, and an https -> http redirect is flagged, because it means
the rest of the visit is no longer encrypted. The whole check, redirects
included, has an overall deadline on top of the per-socket timeout.

Added in v0.1.0
"""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional, cast
from urllib.parse import urljoin, urlsplit

from . import __version__
from .x509 import read_der_fields

DEFAULT_TIMEOUT = 5.0
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 2 * 1024 * 1024   # read at most 2 MB; enough to time the response
DEADLINE_FACTOR = 3                # overall deadline = 3 x timeout unless given
CHUNK_BYTES = 64 * 1024
# OpenSSL's "certificate has expired" verification error number.
X509_V_ERR_CERT_HAS_EXPIRED = 10
CERT_WARN_DAYS = 30
CERT_CRITICAL_DAYS = 7
USER_AGENT = f"NetScope/{__version__}"

# Headers worth showing; the rest are kept in the JSON output.
INTERESTING_HEADERS = ("server", "content-type", "content-length", "location",
                       "strict-transport-security", "cache-control")


@dataclass
class CertInfo:
    subject: Optional[str]
    issuer: Optional[str]
    not_after: Optional[str]          # ISO date the certificate expires
    days_left: Optional[int]
    tls_version: Optional[str]
    # False when the details were read from a certificate that failed
    # verification (second, unchecked connection) - shown as "unverified".
    verified: bool = True
    expired: bool = False             # the verifier itself said "expired"

    @property
    def status(self) -> str:
        if self.expired:
            return "expired"
        if self.days_left is None:
            return "unknown"
        if self.days_left < 0:
            return "expired"
        if self.days_left <= CERT_CRITICAL_DAYS:
            return "critical"
        if self.days_left <= CERT_WARN_DAYS:
            return "warning"
        return "ok"

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "issuer": self.issuer, "not_after": self.not_after,
                "days_left": self.days_left, "status": self.status, "tls_version": self.tls_version,
                "verified": self.verified}


@dataclass
class HttpResult:
    url: str
    final_url: str
    status: Optional[int] = None
    reason: Optional[str] = None
    response_ms: Optional[float] = None   # time until the status line and headers arrived
    total_ms: Optional[float] = None      # time including reading the body
    body_bytes: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    redirects: list[str] = field(default_factory=list)
    cert: Optional[CertInfo] = None
    error: Optional[str] = None
    cert_error: Optional[str] = None      # why certificate verification failed
    findings: list[str] = field(default_factory=list)   # e.g. an https -> http downgrade

    @property
    def ok(self) -> bool:
        return (self.error is None and self.status is not None and self.status < 400
                and not self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "final_url": self.final_url, "status": self.status,
                "reason": self.reason, "ok": self.ok, "response_ms": self.response_ms,
                "total_ms": self.total_ms, "body_bytes": self.body_bytes,
                "redirects": self.redirects, "headers": self.headers,
                "certificate": self.cert.to_dict() if self.cert else None,
                "certificate_error": self.cert_error, "findings": self.findings,
                "error": self.error}


def normalise_url(url: str) -> str:
    """Add ``https://`` when no scheme is given, and reject anything that isn't http(s)."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"only http:// and https:// URLs are supported, not {parts.scheme}://")
    if not parts.hostname:
        raise ValueError(f"'{url}' has no host name")
    return url


def _name_from(cert_field: Any) -> Optional[str]:
    """Pick the common name (CN) - or organisation - out of a certificate's subject/issuer."""
    if not cert_field:
        return None
    values = dict(item for rdn in cert_field for item in rdn)
    return values.get("commonName") or values.get("organizationName")


def parse_cert(cert: Optional[dict], tls_version: Optional[str] = None,
               now: Optional[datetime] = None) -> CertInfo:
    """Turn the dict from ``SSLSocket.getpeercert()`` into a CertInfo."""
    if not cert:
        return CertInfo(None, None, None, None, tls_version)
    not_after_text = cert.get("notAfter")
    not_after, days_left = None, None
    if not_after_text:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after_text), tz=timezone.utc)
        now = now or datetime.now(timezone.utc)
        not_after = expires.date().isoformat()
        days_left = (expires - now).days
    return CertInfo(_name_from(cert.get("subject")), _name_from(cert.get("issuer")),
                    not_after, days_left, tls_version)


def parse_der_cert(der: bytes, tls_version: Optional[str] = None,
                   now: Optional[datetime] = None) -> CertInfo:
    """CertInfo from a raw certificate that was NOT verified (see x509.py)."""
    fields = read_der_fields(der)
    now = now or datetime.now(timezone.utc)
    return CertInfo(fields.subject, fields.issuer, fields.not_after.date().isoformat(),
                    (fields.not_after - now).days, tls_version, verified=False)


def read_unverified_cert(host: str, port: int, timeout: float) -> Optional[CertInfo]:
    """Connect once more WITHOUT checking the certificate, only to read it.

    The TLS handshake is done and the connection closed straight away; no
    HTTP request is sent. Returns None if anything goes wrong.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der, version = tls.getpeercert(binary_form=True), tls.version()
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    try:
        return parse_der_cert(der, version)
    except ValueError:
        return None


def _open_connection(scheme: str, host: str, port: Optional[int], timeout: float,
                     context: Optional[ssl.SSLContext]) -> http.client.HTTPConnection:
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=timeout,
                                           context=context or ssl.create_default_context())
    return http.client.HTTPConnection(host, port, timeout=timeout)


class _DeadlineExceeded(Exception):
    pass


def _host_and_port(url: str) -> tuple[str, str, int]:
    """(scheme, host, port) for one hop, or ValueError if we shouldn't go there."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"redirect to {parts.scheme or 'an unknown'}:// is not followed "
                         "(only http:// and https://)")
    if not parts.hostname:
        raise ValueError(f"redirect to '{url}' has no host name")
    try:
        port = parts.port   # raises ValueError for "abc" or 99999
    except ValueError:
        raise ValueError(f"redirect to '{url}' has an invalid port") from None
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise ValueError(f"redirect to '{url}' has an invalid port")
    return parts.scheme, parts.hostname, port


def _read_body(response: http.client.HTTPResponse, stop_at: float) -> int:
    """Read up to MAX_BODY_BYTES in chunks, giving up once the overall deadline passes."""
    total = 0
    while total < MAX_BODY_BYTES:
        if time.monotonic() > stop_at:
            raise _DeadlineExceeded()
        chunk = response.read(min(CHUNK_BYTES, MAX_BODY_BYTES - total))
        if not chunk:
            break
        total += len(chunk)
    return total


def check_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    method: str = "GET",
    context: Optional[ssl.SSLContext] = None,
    connection_factory: Callable[..., http.client.HTTPConnection] = _open_connection,
    deadline: Optional[float] = None,
    cert_reader: Callable[[str, int, float], Optional[CertInfo]] = read_unverified_cert,
) -> HttpResult:
    """Request ``url`` and report status, timing, headers and (for HTTPS) the certificate.

    ``timeout`` limits each wait on the socket; ``deadline`` (seconds, default
    3 x timeout) limits the whole check including redirects.
    """
    url = normalise_url(url)
    result = HttpResult(url=url, final_url=url)
    overall = deadline if deadline is not None else timeout * DEADLINE_FACTOR
    stop_at = time.monotonic() + overall
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            scheme, host, port = _host_and_port(current)
        except ValueError as exc:
            result.error = str(exc)
            return result
        remaining = stop_at - time.monotonic()
        if remaining <= 0:
            result.error = f"gave up: the whole check took longer than {overall:g} s"
            return result
        result.cert = None   # each hop has its own certificate (or none)
        parts = urlsplit(current)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        start = time.perf_counter()
        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = connection_factory(scheme, host, port, min(timeout, remaining), context)
            # Connect first so we can read the certificate while the socket is
            # still open (http.client may close it as soon as the reply is read).
            conn.connect()
            if scheme == "https" and conn.sock is not None:
                sock = cast(ssl.SSLSocket, conn.sock)  # https connections wrap the socket in TLS
                result.cert = parse_cert(sock.getpeercert(), sock.version())
            conn.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
            response = conn.getresponse()
            result.response_ms = round((time.perf_counter() - start) * 1000, 2)
            body_bytes = _read_body(response, stop_at)
            result.total_ms = round((time.perf_counter() - start) * 1000, 2)
        except ssl.SSLCertVerificationError as exc:
            _record_cert_failure(result, exc, host, port, max(0.1, min(timeout, remaining)),
                                 cert_reader)
            return result
        except ssl.SSLError as exc:
            result.error = f"TLS error: {exc.reason or exc}"
            return result
        except _DeadlineExceeded:
            result.error = f"gave up: the whole check took longer than {overall:g} s"
            return result
        except (TimeoutError, OSError, http.client.HTTPException) as exc:
            result.error = _describe_error(exc)
            return result
        finally:
            if conn is not None:
                conn.close()
        result.status, result.reason = response.status, response.reason
        result.body_bytes = body_bytes
        result.headers = {k.lower(): v for k, v in response.getheaders()}
        location = result.headers.get("location")
        if follow_redirects and response.status in (301, 302, 303, 307, 308) and location:
            target = urljoin(current, location)  # Location can be relative ("/login")
            result.redirects.append(target)
            if scheme == "https" and urlsplit(target).scheme == "http":
                result.findings.append(f"redirect downgrades HTTPS to plain HTTP: {target}")
            current = result.final_url = target
            continue
        return result
    result.error = f"too many redirects (more than {MAX_REDIRECTS})"
    return result


def _record_cert_failure(result: HttpResult, exc: ssl.SSLCertVerificationError, host: str,
                         port: int, timeout: float,
                         cert_reader: Callable[[str, int, float], Optional[CertInfo]]) -> None:
    """Note why verification failed, and read the certificate (unverified) for display."""
    # verify_code/verify_message are set by OpenSSL; read them carefully in
    # case an error was raised without them.
    expired = getattr(exc, "verify_code", None) == X509_V_ERR_CERT_HAS_EXPIRED
    message = getattr(exc, "verify_message", None) or str(exc)
    result.cert_error = "certificate has expired" if expired else message
    result.error = f"certificate problem: {result.cert_error}"
    cert = cert_reader(host, port, timeout)
    if cert is None and expired:
        cert = CertInfo(None, None, None, None, None, verified=False)
    if cert is not None:
        cert.verified = False
        cert.expired = cert.expired or expired
    result.cert = cert


def _describe_error(exc: BaseException) -> str:
    """Short, readable explanation for common network errors."""
    if isinstance(exc, TimeoutError):
        return "timed out waiting for the server"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused (nothing is listening on that port)"
    if isinstance(exc, OSError) and getattr(exc, "strerror", None):
        return str(exc.strerror)
    return str(exc) or exc.__class__.__name__
