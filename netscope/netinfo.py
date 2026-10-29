"""Information about this computer's own network setup.

- Host name and fully qualified name come from the standard ``socket`` module.
- The "main" local IP is found with a neat trick: we create a UDP socket and
  ``connect`` it to a public address. UDP connect sends **no packets**; it
  just asks the OS "which of my addresses would you use to reach that?".
- The list of network interfaces (Wi-Fi, Ethernet, loopback...) needs
  ``psutil``, which is optional. Without it we still show everything else.

Added in v0.1.0
"""
from __future__ import annotations

import platform
import socket
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# Any routable address works for the UDP trick; nothing is actually sent to it.
_PROBE_ADDRESS = ("192.0.2.1", 80)  # TEST-NET-1, reserved for documentation


@dataclass
class Interface:
    name: str
    is_up: Optional[bool]
    speed_mbps: Optional[int]
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    mac: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "is_up": self.is_up, "speed_mbps": self.speed_mbps,
                "ipv4": self.ipv4, "ipv6": self.ipv6, "mac": self.mac}


@dataclass
class NetInfo:
    hostname: str
    fqdn: str
    local_ip: Optional[str]
    os: str
    interfaces: list[Interface] = field(default_factory=list)
    interfaces_note: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {"hostname": self.hostname, "fqdn": self.fqdn, "local_ip": self.local_ip,
                "os": self.os, "interfaces": [i.to_dict() for i in self.interfaces],
                "interfaces_note": self.interfaces_note}


def get_local_ip(socket_factory: Callable[..., socket.socket] = socket.socket) -> Optional[str]:
    """Return the IP address this computer uses for outgoing traffic, or None if offline."""
    sock = socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(_PROBE_ADDRESS)
        return sock.getsockname()[0]
    except OSError:
        return None  # no network route at all (e.g. airplane mode)
    finally:
        sock.close()


def get_interfaces(psutil_module: Any = None) -> tuple[list[Interface], Optional[str]]:
    """List network interfaces using psutil, if installed.

    Returns (interfaces, note). The note explains why the list is empty when
    psutil isn't available, so the user knows how to get it.
    """
    if psutil_module is None:
        try:
            import psutil  # optional dependency
        except ImportError:
            return [], "install psutil to list interfaces: pip install psutil"
        psutil_module = psutil
    addrs = psutil_module.net_if_addrs()
    stats = psutil_module.net_if_stats()
    link_family = getattr(psutil_module, "AF_LINK", None)  # MAC addresses
    interfaces = []
    for name, entries in sorted(addrs.items()):
        stat = stats.get(name)
        iface = Interface(
            name=name,
            is_up=stat.isup if stat else None,
            speed_mbps=(stat.speed or None) if stat else None,  # 0 means "unknown"
        )
        for entry in entries:
            if entry.family == socket.AF_INET:
                iface.ipv4.append(entry.address)
            elif entry.family == socket.AF_INET6:
                iface.ipv6.append(entry.address.split("%")[0])  # drop the "%eth0" zone suffix
            elif link_family is not None and entry.family == link_family:
                iface.mac = entry.address
        interfaces.append(iface)
    return interfaces, None


def collect(psutil_module: Any = None,
            socket_factory: Callable[..., socket.socket] = socket.socket) -> NetInfo:
    """Gather all local network information in one go."""
    interfaces, note = get_interfaces(psutil_module)
    return NetInfo(
        hostname=socket.gethostname(),
        fqdn=socket.getfqdn(),
        local_ip=get_local_ip(socket_factory),
        os=f"{platform.system()} {platform.release()}".strip(),
        interfaces=interfaces,
        interfaces_note=note,
    )
