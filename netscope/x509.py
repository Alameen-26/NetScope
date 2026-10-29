"""Reading a few fields from a raw (DER-encoded) certificate.

Why this exists: when a certificate fails verification - most often because
it has expired - Python refuses the connection, and the only way to still see
*which* certificate the server sent is to connect again without checking it.
On such an unchecked connection ``getpeercert()`` returns an empty dict, so
the certificate's dates and issuer have to be read from its raw bytes.

A certificate is stored in DER: a tree of "tag, length, value" items. We only
walk far enough to find the issuer, the validity dates and the subject:

    Certificate ::= SEQUENCE {
        tbsCertificate SEQUENCE {
            [0] version (optional), serialNumber, signature algorithm,
            issuer Name, validity SEQUENCE { notBefore, notAfter }, subject Name, ...
        }, ...
    }

Anything unexpected raises ValueError; the caller then just shows less detail.

Added in v0.1.0
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

_SEQUENCE, _SET, _CONTEXT_0 = 0x30, 0x31, 0xA0
_OID, _UTC_TIME, _GENERALIZED_TIME = 0x06, 0x17, 0x18
_COMMON_NAME = bytes([0x55, 0x04, 0x03])        # OID 2.5.4.3
_ORGANIZATION = bytes([0x55, 0x04, 0x0A])       # OID 2.5.4.10
_TEXT_TYPES = {0x0C: "utf-8", 0x13: "ascii", 0x14: "latin-1", 0x16: "ascii", 0x1E: "utf-16-be"}


@dataclass
class RawCertFields:
    subject: Optional[str]
    issuer: Optional[str]
    not_before: datetime
    not_after: datetime


def _item(data: bytes, pos: int) -> tuple[int, int, int]:
    """Read one DER item at ``pos``; return (tag, value_start, value_end)."""
    if pos + 2 > len(data):
        raise ValueError("certificate is truncated")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:  # long form: the next N bytes hold the length
        size = length & 0x7F
        if size == 0 or size > 4 or pos + size > len(data):
            raise ValueError("bad length in certificate")
        length = int.from_bytes(data[pos:pos + size], "big")
        pos += size
    if pos + length > len(data):
        raise ValueError("certificate is truncated")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    items = []
    while start < end:
        item = _item(data, start)
        items.append(item)
        start = item[2]
    return items


def _name(data: bytes, start: int, end: int) -> Optional[str]:
    """Common name (or organisation) from a Name: SEQUENCE OF SET OF {OID, value}."""
    found: dict[bytes, str] = {}
    for tag, s, e in _children(data, start, end):
        if tag != _SET:
            continue
        for _, ps, pe in _children(data, s, e):
            parts = _children(data, ps, pe)
            if len(parts) == 2 and parts[0][0] == _OID:
                oid = data[parts[0][1]:parts[0][2]]
                value_tag, vs, ve = parts[1]
                encoding = _TEXT_TYPES.get(value_tag)
                if encoding:
                    found[oid] = data[vs:ve].decode(encoding, errors="replace")
    return found.get(_COMMON_NAME) or found.get(_ORGANIZATION)


def _time(data: bytes, item: tuple[int, int, int]) -> datetime:
    tag, start, end = item
    text = data[start:end].decode("ascii")
    if tag == _UTC_TIME:   # YYMMDDHHMMSSZ; years 50-99 mean 19xx
        year = int(text[:2])
        text = ("19" if year >= 50 else "20") + text
    elif tag != _GENERALIZED_TIME:
        raise ValueError("unexpected date format in certificate")
    return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def read_der_fields(der: bytes) -> RawCertFields:
    """Issuer, subject and validity dates from a DER certificate."""
    tag, start, end = _item(der, 0)
    if tag != _SEQUENCE:
        raise ValueError("not a certificate")
    tag, start, end = _item(der, start)       # tbsCertificate
    if tag != _SEQUENCE:
        raise ValueError("not a certificate")
    fields = _children(der, start, end)
    if fields and fields[0][0] == _CONTEXT_0:
        fields = fields[1:]                     # skip the optional version
    if len(fields) < 5:
        raise ValueError("certificate is missing fields")
    _serial, _algorithm, issuer, validity, subject = fields[:5]
    dates = _children(der, validity[1], validity[2])
    if len(dates) != 2:
        raise ValueError("certificate has no validity dates")
    return RawCertFields(subject=_name(der, subject[1], subject[2]),
                         issuer=_name(der, issuer[1], issuer[2]),
                         not_before=_time(der, dates[0]), not_after=_time(der, dates[1]))
