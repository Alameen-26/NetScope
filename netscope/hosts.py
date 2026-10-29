"""Checking and resolving the host names people type on the command line.

Two jobs:

1. **Validate.** ``ping`` and ``trace`` hand the target to another program.
   A "host" such as ``-f`` or ``/?`` would be read by that program as an
   *option*, not a host (``ping -f`` floods on Linux). So anything starting
   with ``-`` (or ``/`` on Windows, where options start with a slash), or
   containing characters that can't appear in a host name or IP address, is
   rejected before any program runs.
2. **Resolve once.** We look the name up ourselves and pass the resulting IP
   address to the other program. Then the program only ever sees an address,
   and every command reports an unknown host the same way.

Added in v0.1.0
"""
from __future__ import annotations

import platform
import re
import socket
from typing import Callable, Optional

# Letters, digits, dots, colons (IPv6), "%" (IPv6 zone such as fe80::1%eth0),
# "_" and "-". Nothing else appears in a host name or an IP address.
_ALLOWED = re.compile(r"^[A-Za-z0-9.:%_-]+$")
MAX_HOST_LENGTH = 253   # longest legal DNS name


class InvalidHost(ValueError):
    """The text can't be a host name or IP address (a usage error)."""


class UnknownHost(OSError):
    """The name is well-formed but couldn't be resolved to an address."""


def validate_host(text: str, system: Optional[str] = None) -> str:
    """Return ``text`` stripped of spaces, or raise InvalidHost explaining why it's not allowed."""
    host = text.strip()
    system = system or platform.system()
    if not host:
        raise InvalidHost("no host given")
    if host.startswith("-") or (system == "Windows" and host.startswith("/")):
        raise InvalidHost(f"'{host}' looks like an option, not a host name")
    if len(host) > MAX_HOST_LENGTH or not _ALLOWED.match(host):
        raise InvalidHost(f"'{host}' is not a valid host name or IP address "
                          "(allowed: letters, digits and . : % _ -)")
    return host


def resolve(host: str, resolver: Callable[..., list] = socket.getaddrinfo) -> tuple[str, int]:
    """Look up ``host`` once and return (ip, address_family).

    IPv4 is preferred when a name has both kinds of address (e.g. "localhost"
    -> 127.0.0.1 rather than ::1), because most home routers and local
    services listen on IPv4. Raises UnknownHost if the lookup fails.
    """
    try:
        info = resolver(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnknownHost(f"could not resolve '{host}': {exc.strerror or exc}") from None
    except UnicodeError:
        raise UnknownHost(f"could not resolve '{host}': invalid name") from None
    if not info:
        raise UnknownHost(f"could not resolve '{host}': no addresses found")
    ipv4 = [entry for entry in info if entry[0] == socket.AF_INET]
    family, _, _, _, sockaddr = (ipv4 or info)[0]
    return str(sockaddr[0]), int(family)
