"""Shared test setup.

The ``block_outside_network`` fixture runs for every test. It makes any
attempt to connect somewhere other than this computer (anything in 127.0.0.0/8, or ::1) fail
loudly, so the suite can never depend on - or bother - the real internet.
Tests that need a server start a tiny one on 127.0.0.1 instead.

Every blocked attempt is also written down and checked when the test ends,
so the test still fails even if the code under test catches the error (the
CLI turns unexpected errors into a one-line message, for example).

Added in v0.1.0
"""
from __future__ import annotations

import http.server
import ipaddress
import socket
import ssl
import threading
from pathlib import Path
from typing import Iterator

import pytest

_LOCAL = {"127.0.0.1", "::1", "localhost"}
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_getaddrinfo = socket.getaddrinfo


def _is_local(host: object) -> bool:
    if host in _LOCAL:
        return True
    try:
        return ipaddress.ip_address(str(host)).is_loopback  # all of 127.0.0.0/8
    except ValueError:
        return False


_blocked: list[str] = []
DATA = Path(__file__).parent / "data"


def _guard(address: object) -> None:
    host = address[0] if isinstance(address, tuple) else address
    if not _is_local(host):
        _blocked.append(f"connect {address!r}")
        raise AssertionError(f"test tried to reach the network: {address!r}")


@pytest.fixture(autouse=True)
def block_outside_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _blocked.clear()

    def connect(self: socket.socket, address: object) -> None:
        _guard(address)
        return _real_connect(self, address)

    def connect_ex(self: socket.socket, address: object) -> int:
        _guard(address)
        return _real_connect_ex(self, address)

    def getaddrinfo(host: object, *args: object, **kwargs: object) -> list:
        # DNS lookups are network traffic too: only "localhost" and IP literals allowed.
        if host is not None and not _is_local(host):
            try:
                ipaddress.ip_address(str(host))
            except ValueError:
                _blocked.append(f"DNS lookup {host!r}")
                raise AssertionError(f"test tried a real DNS lookup: {host!r}") from None
        return _real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    yield
    assert not _blocked, f"test tried to use the real network: {_blocked}"


@pytest.fixture
def listening_port() -> Iterator[int]:
    """A TCP port on 127.0.0.1 with something listening on it (an "open" port)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))   # port 0 = "pick any free port"
    server.listen(16)
    yield server.getsockname()[1]
    server.close()


@pytest.fixture
def closed_port() -> int:
    """A port on 127.0.0.1 that nothing is listening on (a "closed" port)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # free it again, so connections are refused
    return port


class _Handler(http.server.BaseHTTPRequestHandler):
    """Tiny web server with a few routes the HTTP tests use."""

    def do_GET(self) -> None:  # noqa: N802 (name required by http.server)
        routes = {
            "/": (200, b"hello"),
            "/missing": (404, b"nope"),
            "/teapot": (418, b"short and stout"),
        }
        redirects = {
            "/old": "/",
            "/to-file": "file:///etc/passwd",          # must not be followed
            "/to-ftp": "ftp://127.0.0.1/x",
            "/bad-port": "http://127.0.0.1:99999/",
            "/no-host": "http:///nowhere",
        }
        if self.path in redirects:
            self._reply(301, b"", {"Location": redirects[self.path]})
        elif self.path == "/to-http" and getattr(self.server, "plain_url", None):
            self._reply(302, b"", {"Location": self.server.plain_url + "/"})  # type: ignore[attr-defined]
        elif self.path == "/loop":
            self._reply(302, b"", {"Location": "/loop"})
        elif self.path in routes:
            status, body = routes[self.path]
            self._reply(status, body, {"Content-Type": "text/plain", "X-Test": "<b>yes</b>"})
        else:
            self._reply(404, b"", {})

    do_HEAD = do_GET

    def _reply(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep test output quiet
        pass


@pytest.fixture
def http_server() -> Iterator[str]:
    """Start a local web server in a background thread; yields its base URL."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _https_server(cert_name: str, plain_url: str = "") -> tuple[http.server.ThreadingHTTPServer, str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(DATA / f"{cert_name}_cert.pem", DATA / f"{cert_name}_key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.plain_url = plain_url  # type: ignore[attr-defined]
    # A client that hangs up after the handshake (as the certificate reader
    # does) is normal here; don't print its traceback.
    server.handle_error = lambda request, client_address: None  # type: ignore[method-assign]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"https://127.0.0.1:{server.server_address[1]}"


def trust(cert_name: str) -> ssl.SSLContext:
    """A client context that trusts only our test certificate (so its real problems show)."""
    return ssl.create_default_context(cafile=str(DATA / f"{cert_name}_cert.pem"))


@pytest.fixture
def expired_https_server() -> Iterator[str]:
    """HTTPS on 127.0.0.1 with a certificate that expired on 2021-01-01 (test-only key)."""
    server, url = _https_server("expired")
    yield url
    server.shutdown()
    server.server_close()


@pytest.fixture
def valid_https_server(http_server: str) -> Iterator[str]:
    """HTTPS on 127.0.0.1 (valid until 2099); its /to-http redirects to plain ``http_server``."""
    server, url = _https_server("valid", plain_url=http_server)
    yield url
    server.shutdown()
    server.server_close()
