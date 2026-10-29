"""Guard rails: decide whether a target is "yours" before scanning it.

Scanning your own computer or home network is fine. Scanning someone else's
network can break the law or a school/work policy. So before the port scanner
runs, every target is sorted into one of these groups:

    loopback   127.0.0.1 / ::1 - this computer talking to itself      -> allowed
    private    10.x, 172.16-31.x, 192.168.x, fc00::/7 - home/office    -> allowed
    link-local 169.254.x / fe80:: - same cable or Wi-Fi only            -> allowed
    shared     100.64.0.0/10 (carrier-grade NAT) - belongs to your ISP  -> ask first
    public     everything else - the wider internet                     -> limited

"Ask first" means the scan is refused unless you pass ``--i-own-this``.
Public single hosts and small ranges (/24 or smaller) are allowed with a
warning; bigger public ranges are refused unless you pass ``--i-own-this``.

Note: Python's ``ipaddress`` treats 100.64.0.0/10 as neither private nor
global, so it needs its own check - otherwise it would slip through as "public".

IPv6 addresses that carry an IPv4 address inside them are judged by that IPv4
address, because that's where the traffic really ends up:

    ::ffff:1.2.3.4     "IPv4-mapped" - the same as 1.2.3.4
    64:ff9b::1.2.3.4   NAT64 - a gateway forwards it to 1.2.3.4
    2002:0102:0304::   6to4 - tunnelled to 1.2.3.4

Without this, ``::ffff:8.8.8.8`` would look like an odd IPv6 address, and
Python 3.10 and 3.13 even disagree about whether such addresses are private.

Added in v0.1.0
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional, Union

from . import RESPONSIBLE_USE

LOOPBACK = "loopback"
PRIVATE = "private"
LINK_LOCAL = "link-local"
SHARED = "shared"        # carrier-grade NAT, RFC 6598
PUBLIC = "public"

ALLOWED_KINDS = {LOOPBACK, PRIVATE, LINK_LOCAL}
CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")
MAPPED_NETWORK = ipaddress.IPv6Network("::ffff:0:0/96")     # IPv4-mapped IPv6
NAT64_NETWORK = ipaddress.IPv6Network("64:ff9b::/96")       # well-known NAT64 prefix
SIXTOFOUR_NETWORK = ipaddress.IPv6Network("2002::/16")      # 6to4 tunnels
MAX_PUBLIC_PREFIX_V4 = 24     # a public IPv4 range bigger than /24 needs the flag
MAX_PUBLIC_PREFIX_V6 = 120    # same number of addresses (256) for IPv6
MAX_HOSTS = 1024              # hard limit per scan, even on your own network

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def embedded_ipv4(net: Network) -> Optional[ipaddress.IPv4Network]:
    """The IPv4 range hidden inside an IPv4-mapped, NAT64 or 6to4 IPv6 range, if any.

    The IPv4 address sits in fixed bits: the last 32 bits for mapped and
    NAT64 addresses, bits 16-48 for 6to4. Ranges that only partly overlap
    these blocks are far too large to scan anyway (see MAX_HOSTS).
    """
    if not isinstance(net, ipaddress.IPv6Network):
        return None
    if net.subnet_of(MAPPED_NETWORK) or net.subnet_of(NAT64_NETWORK):
        return ipaddress.IPv4Network((int(net.network_address) & 0xFFFFFFFF, net.prefixlen - 96))
    if net.subnet_of(SIXTOFOUR_NETWORK):
        ipv4 = (int(net.network_address) >> 80) & 0xFFFFFFFF
        # A 6to4 range longer than /48 still points at one single IPv4 host.
        return ipaddress.IPv4Network((ipv4, min(net.prefixlen, 48) - 16), strict=False)
    return None


def effective_network(net: Network) -> Network:
    """The range traffic really goes to: the embedded IPv4 range, or ``net`` itself."""
    return embedded_ipv4(net) or net


def classify_address(ip: str) -> str:
    """Return LOOPBACK, PRIVATE, LINK_LOCAL, SHARED or PUBLIC for one IP address.

    Raises ValueError if ``ip`` is not a valid IPv4/IPv6 address.
    """
    return classify_network(ipaddress.ip_network(ipaddress.ip_address(ip)))


def classify_network(net: Network) -> str:
    """Classify a whole range. A range is only "allowed" if it sits entirely inside one."""
    net = effective_network(net)
    # Order matters: loopback and link-local are also "private" in Python's
    # eyes, so check the more specific groups first - except CGNAT, where any
    # overlap counts, so a wide range can't hide it.
    if isinstance(net, ipaddress.IPv4Network) and net.overlaps(CGNAT_NETWORK):
        return SHARED
    if net.is_loopback:
        return LOOPBACK
    if net.is_link_local:
        return LINK_LOCAL
    if net.is_private:
        return PRIVATE
    return PUBLIC


@dataclass
class Decision:
    """The guard rail's answer for one target."""

    allowed: bool
    kind: str
    message: Optional[str] = None   # why it was refused, or a warning to show


def check_target(network: Network, i_own_this: bool = False) -> Decision:
    """Decide whether scanning ``network`` (a single host is a /32 or /128) is allowed."""
    kind = classify_network(network)
    if network.num_addresses > MAX_HOSTS + 2:  # +2 for network/broadcast addresses
        return Decision(False, kind, f"{network} has {network.num_addresses} addresses; "
                        f"the limit is {MAX_HOSTS} per scan. Split it into smaller ranges.")
    if kind in ALLOWED_KINDS:
        return Decision(True, kind)
    if i_own_this:
        return Decision(True, kind, f"--i-own-this given. {RESPONSIBLE_USE}")
    if kind == SHARED:
        return Decision(False, kind, f"{network} is in 100.64.0.0/10 (carrier-grade NAT), "
                        "which belongs to your internet provider, not you. "
                        "Pass --i-own-this only if you are authorized to scan it.")
    # Judge the size of a mapped/NAT64/6to4 range by the IPv4 range it reaches.
    effective = effective_network(network)
    limit = MAX_PUBLIC_PREFIX_V4 if effective.version == 4 else MAX_PUBLIC_PREFIX_V6
    if effective.prefixlen < limit:
        shown = f"{network} ({effective})" if effective != network else str(network)
        return Decision(False, kind, f"{shown} is a public range larger than /{limit}. "
                        "Pass --i-own-this only if you own it or have written permission.")
    return Decision(True, kind, f"{network} is a public address. {RESPONSIBLE_USE}")


def is_local_target(ip: str) -> bool:
    """True when the address is on this machine or the local network."""
    return classify_address(ip) in ALLOWED_KINDS
