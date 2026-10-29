"""HTTPS problems, redirect safety and the overall deadline, against servers on 127.0.0.1.

The certificates in tests/data are test-only, self-signed, for 127.0.0.1.
"""
from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from netscope import __main__ as cli
from netscope.httpcheck import (X509_V_ERR_CERT_HAS_EXPIRED, CertInfo, check_url, parse_der_cert,
                                read_unverified_cert)
from netscope.x509 import read_der_fields

from conftest import trust

DATA = Path(__file__).parent / "data"


def der(name: str) -> bytes:
    import ssl
    return ssl.PEM_cert_to_DER_cert((DATA / f"{name}_cert.pem").read_text(encoding="ascii"))


def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# ---- reading a certificate without trusting it (M4)

def test_read_der_fields_of_expired_cert():
    fields = read_der_fields(der("expired"))
    assert fields.subject == "localhost" and fields.issuer == "localhost"
    assert fields.not_before == datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert fields.not_after == datetime(2021, 1, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize("bad", [b"", b"\x30", b"\x30\x82\xff\xff", b"not a certificate", der("valid")[:40]])
def test_read_der_fields_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        read_der_fields(bad)


def test_parse_der_cert_is_marked_unverified():
    info = parse_der_cert(der("expired"), "TLSv1.3", now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert info.verified is False and info.not_after == "2021-01-01"
    assert info.days_left is not None and info.days_left < 0 and info.status == "expired"
    assert info.to_dict()["verified"] is False


def test_expired_certificate_is_reported(expired_https_server):
    result = check_url(expired_https_server + "/", timeout=3, context=trust("expired"))
    assert result.cert_error == "certificate has expired"
    assert result.status is None and not result.ok
    # The certificate was read again, unverified, from 127.0.0.1 - only to show it.
    assert result.cert is not None and result.cert.verified is False and result.cert.expired
    assert result.cert.not_after == "2021-01-01" and result.cert.subject == "localhost"
    assert result.to_dict()["certificate_error"] == "certificate has expired"


def test_expired_code_constant():
    assert X509_V_ERR_CERT_HAS_EXPIRED == 10


def test_read_unverified_cert_from_local_server(expired_https_server):
    port = int(expired_https_server.rsplit(":", 1)[1])
    info = read_unverified_cert("127.0.0.1", port, 3)
    assert info is not None and info.subject == "localhost" and info.verified is False


def test_read_unverified_cert_failure_is_none(closed_port):
    assert read_unverified_cert("127.0.0.1", closed_port, 1) is None


def test_cli_expired_certificate_is_exit_1(expired_https_server, capsys):
    code, out, _ = run(capsys, "http", expired_https_server + "/", "-t", "3")
    assert code == cli.EXIT_FINDINGS
    assert "NOT trusted" in out and "(unverified)" in out and "2021-01-01" in out


def test_cert_failure_without_readable_cert_still_flags_expiry():
    import ssl

    class Expired:
        sock = None

        def __init__(self, *a):
            pass

        def connect(self):
            err = ssl.SSLCertVerificationError("certificate verify failed")
            err.verify_code = X509_V_ERR_CERT_HAS_EXPIRED
            err.verify_message = "certificate has expired"
            raise err

        def close(self):
            pass
    result = check_url("https://127.0.0.1/", connection_factory=Expired, cert_reader=lambda *a: None)
    assert result.cert is not None and result.cert.expired and result.cert.status == "expired"


# ---- a good certificate, and redirect safety (L2)

def test_valid_certificate(valid_https_server):
    result = check_url(valid_https_server + "/", timeout=3, context=trust("valid"))
    assert result.ok and result.cert is not None and result.cert.verified
    assert result.cert.subject == "localhost"


def test_https_to_http_downgrade_is_flagged(valid_https_server, http_server):
    result = check_url(valid_https_server + "/to-http", timeout=3, context=trust("valid"))
    assert result.status == 200 and result.final_url == http_server + "/"
    assert any("downgrades HTTPS to plain HTTP" in f for f in result.findings)
    assert not result.ok
    # The certificate belongs to the first hop only; the final hop is plain HTTP.
    assert result.cert is None


def test_cli_downgrade_is_a_finding(valid_https_server, monkeypatch, capsys):
    import netscope.httpcheck as httpcheck
    real = httpcheck.check_url
    monkeypatch.setattr(httpcheck, "check_url", lambda url, **kw: real(url, context=trust("valid"), **kw))
    code, out, _ = run(capsys, "http", valid_https_server + "/to-http")
    assert code == cli.EXIT_FINDINGS and "Finding: redirect downgrades" in out


@pytest.mark.parametrize("path, words", [
    ("/to-file", "file:// is not followed"),
    ("/to-ftp", "ftp:// is not followed"),
    ("/bad-port", "invalid port"),
])
def test_unsafe_redirects_are_not_followed(http_server, path, words):
    result = check_url(http_server + path, timeout=3)
    assert result.status == 301 and words in (result.error or "") and not result.ok


def test_redirect_checks_each_hop():
    from netscope.httpcheck import _host_and_port
    assert _host_and_port("https://127.0.0.1/x") == ("https", "127.0.0.1", 443)
    assert _host_and_port("http://127.0.0.1:8080/") == ("http", "127.0.0.1", 8080)
    for bad, words in [("http:///x", "no host name"), ("http://127.0.0.1:0/", "invalid port"),
                       ("http://127.0.0.1:abc/", "invalid port"), ("javascript:alert(1)", "not followed")]:
        with pytest.raises(ValueError, match=words):
            _host_and_port(bad)


def test_cli_file_redirect_is_clean(http_server, capsys):
    code, out, err = run(capsys, "http", http_server + "/to-file")
    assert code == cli.EXIT_FINDINGS and "file:// is not followed" in out and "Traceback" not in err


def test_connection_failure_inside_try():
    def broken_factory(*a):
        raise OSError(101, "Network is unreachable")
    result = check_url("http://127.0.0.1:9/", connection_factory=broken_factory)
    assert result.status is None and result.error == "Network is unreachable"


# ---- overall deadline (L6)

@pytest.fixture
def dripping_server():
    """Sends a big body very slowly, so only an overall deadline can stop the check."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    stop = threading.Event()

    def serve():
        server.settimeout(5)
        try:
            conn, _ = server.accept()
        except OSError:
            return
        with conn:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10000000\r\n\r\n")
            while not stop.is_set():
                try:
                    conn.sendall(b"x" * 65536)
                except OSError:
                    return
                time.sleep(0.15)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.getsockname()[1]}"
    stop.set()
    server.close()
    thread.join(2)


def test_overall_deadline_stops_a_slow_download(dripping_server):
    start = time.perf_counter()
    result = check_url(dripping_server + "/", timeout=3, deadline=0.6)
    elapsed = time.perf_counter() - start
    assert "gave up" in (result.error or "") and elapsed < 2.5


def test_deadline_also_covers_redirects(http_server, monkeypatch):
    # Pretend each hop takes 1 s of the clock: the deadline is hit between hops.
    import netscope.httpcheck as httpcheck
    clock = {"t": 0.0}

    def tick():
        clock["t"] += 1.0
        return clock["t"]
    monkeypatch.setattr(httpcheck.time, "monotonic", tick)
    result = check_url(http_server + "/loop", timeout=3, deadline=2.5)
    assert "gave up" in (result.error or "")


def test_cert_info_status_expired_flag():
    info = CertInfo("a", "b", "2099-01-01", 9999, "TLSv1.3", verified=False, expired=True)
    assert info.status == "expired"
