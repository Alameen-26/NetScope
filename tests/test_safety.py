"""Tests for the scanning guard rails in netscope.safety."""
from __future__ import annotations

import ipaddress

import pytest

from netscope import safety
from netscope.safety import check_target, classify_address, classify_network, is_local_target


def net(text: str):
    return ipaddress.ip_network(text, strict=False)


@pytest.mark.parametrize("ip, kind", [
    ("127.0.0.1", safety.LOOPBACK), ("::1", safety.LOOPBACK),
    ("192.168.1.10", safety.PRIVATE), ("10.0.0.5", safety.PRIVATE), ("172.20.1.1", safety.PRIVATE),
    ("fd00::1", safety.PRIVATE),
    ("169.254.10.1", safety.LINK_LOCAL), ("fe80::1", safety.LINK_LOCAL),
    ("100.64.0.1", safety.SHARED), ("100.127.255.254", safety.SHARED),
    ("8.8.8.8", safety.PUBLIC), ("2606:4700::1111", safety.PUBLIC),
    ("100.128.0.1", safety.PUBLIC),  # just outside the CGNAT block
])
def test_classify_address(ip, kind):
    assert classify_address(ip) == kind


def test_cgnat_is_neither_private_nor_global_in_python():
    # The reason SHARED needs its own check: ipaddress puts it in neither group.
    addr = ipaddress.ip_address("100.64.0.1")
    assert not addr.is_private and not addr.is_global


def test_invalid_address_raises():
    with pytest.raises(ValueError):
        classify_address("not-an-ip")


def test_is_local_target():
    assert is_local_target("192.168.0.1")
    assert not is_local_target("100.64.0.1")
    assert not is_local_target("1.1.1.1")


@pytest.mark.parametrize("target", ["127.0.0.1/32", "192.168.1.0/24", "10.0.0.0/22", "fe80::/118"])
def test_own_networks_are_allowed_without_flag(target):
    decision = check_target(net(target))
    assert decision.allowed and decision.message is None


def test_cgnat_needs_the_flag():
    decision = check_target(net("100.64.1.1/32"))
    assert not decision.allowed and decision.kind == safety.SHARED
    assert "--i-own-this" in decision.message
    assert check_target(net("100.64.1.1/32"), i_own_this=True).allowed


def test_range_overlapping_cgnat_counts_as_shared():
    assert classify_network(net("100.64.0.0/9")) == safety.SHARED


def test_single_public_host_allowed_with_warning():
    decision = check_target(net("8.8.8.8/32"))
    assert decision.allowed and decision.kind == safety.PUBLIC
    assert "public" in decision.message


def test_public_slash24_allowed_but_larger_refused():
    assert check_target(net("203.0.113.0/24")).allowed  # documentation range counts as private
    assert check_target(net("8.8.8.0/24")).allowed
    refused = check_target(net("8.8.8.0/23"))
    assert not refused.allowed and "larger than /24" in refused.message


def test_flag_allows_large_public_range_and_repeats_responsible_use():
    decision = check_target(net("8.8.8.0/23"), i_own_this=True)
    assert decision.allowed
    assert safety.RESPONSIBLE_USE in decision.message


def test_public_ipv6_range_limit():
    assert check_target(net("2606:4700::/120")).allowed
    assert not check_target(net("2606:4700::/119")).allowed


def test_hard_host_limit_applies_even_to_private_and_with_flag():
    for flag in (False, True):
        decision = check_target(net("10.0.0.0/16"), i_own_this=flag)
        assert not decision.allowed and "limit" in decision.message
