"""Tests for netscope.httpcheck against a local web server on 127.0.0.1."""
from __future__ import annotations

import socket
from datetime import datetime, timezone

import pytest

from netscope import httpcheck
from netscope.httpcheck import CertInfo, check_url, normalise_url, parse_cert


# ---- URL handling

@pytest.mark.parametrize("given, expected", [
    ("example.com", "https://example.com"),
    ("http://example.com/x", "http://example.com/x"),
    ("  https://a.b  ", "https://a.b"),
])
def test_normalise_url(given, expected):
    assert normalise_url(given) == expected


@pytest.mark.parametrize("bad", ["ftp://example.com", "https://"])
def test_normalise_url_rejects(bad):
    with pytest.raises(ValueError):
        normalise_url(bad)


# ---- real requests to the local test server

def test_ok_response(http_server):
    result = check_url(http_server + "/")
    assert result.ok and result.status == 200 and result.reason == "OK"
    assert result.body_bytes == 5
    assert result.response_ms is not None and result.total_ms >= result.response_ms
    assert result.headers["content-type"] == "text/plain"
    assert result.cert is None  # plain http has no certificate


def test_error_status_is_not_ok(http_server):
    result = check_url(http_server + "/missing")
    assert result.status == 404 and not result.ok and result.error is None


def test_follows_relative_redirect(http_server):
    result = check_url(http_server + "/old")
    assert result.status == 200
    assert result.redirects == [http_server + "/"] and result.final_url == http_server + "/"


def test_no_redirects_option(http_server):
    result = check_url(http_server + "/old", follow_redirects=False)
    assert result.status == 301 and result.headers["location"] == "/"


def test_redirect_loop_is_stopped(http_server):
    result = check_url(http_server + "/loop")
    assert "too many redirects" in result.error
    assert len(result.redirects) == httpcheck.MAX_REDIRECTS + 1


def test_head_request(http_server):
    result = check_url(http_server + "/", method="HEAD")
    assert result.status == 200 and result.body_bytes == 0


def test_query_string_is_sent(http_server):
    assert check_url(http_server + "/?a=1").status == 404  # handler only matches "/" exactly


def test_connection_refused(closed_port):
    result = check_url(f"http://127.0.0.1:{closed_port}/", timeout=5)
    assert result.status is None and "refused" in result.error


def test_timeout_is_reported():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)  # accepts the connection but never answers
    try:
        result = check_url(f"http://127.0.0.1:{server.getsockname()[1]}/", timeout=0.3)
    finally:
        server.close()
    assert result.status is None and "timed out" in result.error


# ---- certificates

CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("organizationName", "Example CA"),), (("commonName", "Example CA R3"),)),
    "notAfter": "Jan 30 12:00:00 2027 GMT",
}
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)


def test_parse_cert():
    info = parse_cert(CERT, "TLSv1.3", now=NOW)
    assert info.subject == "example.com" and info.issuer == "Example CA R3"
    assert info.not_after == "2027-01-30" and info.days_left == 93
    assert info.status == "ok" and info.to_dict()["tls_version"] == "TLSv1.3"


def test_parse_cert_empty():
    assert parse_cert({}).status == "unknown"


@pytest.mark.parametrize("days, status", [(-1, "expired"), (0, "critical"), (7, "critical"),
                                          (8, "warning"), (30, "warning"), (31, "ok")])
def test_cert_status_thresholds(days, status):
    assert CertInfo("a", "b", "x", days, None).status == status


class FakeTlsSock:
    def getpeercert(self):
        return CERT

    def version(self):
        return "TLSv1.3"


class FakeResponse:
    status, reason = 200, "OK"

    def read(self, n):
        return b"ok"

    def getheaders(self):
        return [("Server", "fake")]


class FakeHttpsConn:
    def __init__(self, *a):
        self.sock = None

    def connect(self):
        self.sock = FakeTlsSock()

    def request(self, *a, **k):
        pass

    def getresponse(self):
        return FakeResponse()

    def close(self):
        self.sock = None


def test_https_reads_certificate_with_fake_connection():
    result = check_url("https://example.com", connection_factory=FakeHttpsConn)
    assert result.ok and result.cert.subject == "example.com"
    assert result.cert.tls_version == "TLSv1.3"
    assert result.to_dict()["certificate"]["issuer"] == "Example CA R3"


def test_tls_errors_are_explained():
    import ssl

    class BadCert(FakeHttpsConn):
        def connect(self):
            err = ssl.SSLCertVerificationError("certificate verify failed")
            err.verify_message = "certificate has expired"
            raise err
    result = check_url("https://expired.test", connection_factory=BadCert,
                       cert_reader=lambda *a: None)
    assert result.error == "certificate problem: certificate has expired"
