"""TLS ClientHello parser and JA4-style fingerprint generator.

Extracts:
- SNI (Server Name Indication)
- ALPN (Application Layer Protocol Negotiation)
- Cipher suite list (filtering GREASE)
- Supported versions (including TLS 1.3)
- Deterministic JA4-style fingerprint hash

Robustness:
- Safely handles truncated packets, non-TLS traffic, and fragmented records without throwing unhandled exceptions.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any

# TLS Record & Handshake constants
RECORD_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01

# Common TLS Extensions
EXT_SERVER_NAME = 0x0000
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_SIGNATURE_ALGORITHMS = 0x000D

# GREASE values (RFC 8701) to ignore when fingerprinting: 0x?a?a
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBAAA, 0xCAAA, 0xDAAA, 0xEAAA, 0xFAFA,
}


def is_grease(val: int) -> bool:
    return val in GREASE_VALUES or ((val & 0x0F0F) == 0x0A0A and ((val >> 8) == (val & 0xFF)))


@dataclass
class TLSClientHello:
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    version: int = 0x0303
    supported_versions: list[int] = field(default_factory=list)
    ja4: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sni": self.sni,
            "alpn": self.alpn,
            "ciphers_count": len(self.ciphers),
            "extensions_count": len(self.extensions),
            "ja4": self.ja4,
        }


def parse_client_hello(payload: bytes) -> TLSClientHello | None:
    """Parse a TLS ClientHello from payload bytes.

    Tolerates packet boundaries, non-TLS packets, and truncated records.
    Returns None if payload is not a valid ClientHello.
    """
    if len(payload) < 5:
        return None

    # Check TLS Record header: content_type == 0x16 (Handshake)
    content_type, rec_ver, rec_len = struct.unpack("!BHH", payload[:5])
    if content_type != RECORD_HANDSHAKE:
        return None

    # Check if record has handshake message
    if len(payload) < 9:
        return None

    msg_type = payload[5]
    if msg_type != HANDSHAKE_CLIENT_HELLO:
        return None

    # 3-byte handshake length
    msg_len = int.from_bytes(payload[6:9], "big")
    if len(payload) < 9 + min(msg_len, 30):
        # Header severely truncated
        return None

    offset = 9
    end = min(len(payload), 9 + msg_len)

    # Client Version (2 bytes)
    if offset + 2 > end:
        return None
    client_ver = struct.unpack("!H", payload[offset : offset + 2])[0]
    offset += 2

    # Random (32 bytes)
    if offset + 32 > end:
        return None
    offset += 32

    # Session ID length (1 byte)
    if offset + 1 > end:
        return None
    sess_id_len = payload[offset]
    offset += 1 + sess_id_len
    if offset > end:
        return None

    # Cipher Suites
    if offset + 2 > end:
        return None
    ciphers_len = struct.unpack("!H", payload[offset : offset + 2])[0]
    offset += 2
    if offset + ciphers_len > end:
        return None

    ciphers: list[int] = []
    for i in range(0, ciphers_len, 2):
        if offset + i + 2 <= end:
            c = struct.unpack("!H", payload[offset + i : offset + i + 2])[0]
            if not is_grease(c):
                ciphers.append(c)
    offset += ciphers_len

    # Compression Methods
    if offset + 1 > end:
        return None
    comp_len = payload[offset]
    offset += 1 + comp_len
    if offset > end:
        return None

    # Extensions
    sni: str | None = None
    alpn: list[str] = []
    extensions: list[int] = []
    supported_versions: list[int] = []

    if offset + 2 <= end:
        exts_len = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2
        ext_end = min(end, offset + exts_len)

        while offset + 4 <= ext_end:
            ext_type, ext_size = struct.unpack("!HH", payload[offset : offset + 4])
            offset += 4
            if offset + ext_size > ext_end:
                break
            ext_data = payload[offset : offset + ext_size]
            offset += ext_size

            if not is_grease(ext_type):
                extensions.append(ext_type)

            # Extension: Server Name (0x0000)
            if ext_type == EXT_SERVER_NAME:
                sni = _parse_sni(ext_data)

            # Extension: ALPN (0x0010)
            elif ext_type == EXT_ALPN:
                alpn = _parse_alpn(ext_data)

            # Extension: Supported Versions (0x002B)
            elif ext_type == EXT_SUPPORTED_VERSIONS:
                supported_versions = _parse_supported_versions(ext_data)

    # Compute JA4 fingerprint
    ja4 = compute_ja4(
        protocol="t",  # TCP
        tls_version=supported_versions[0] if supported_versions else client_ver,
        has_sni=sni is not None,
        ciphers=ciphers,
        extensions=extensions,
        alpn=alpn,
    )

    return TLSClientHello(
        sni=sni,
        alpn=alpn,
        ciphers=ciphers,
        extensions=extensions,
        version=client_ver,
        supported_versions=supported_versions,
        ja4=ja4,
    )


def _parse_sni(data: bytes) -> str | None:
    try:
        if len(data) < 2:
            return None
        list_len = struct.unpack("!H", data[:2])[0]
        offset = 2
        while offset + 3 <= len(data):
            name_type = data[offset]
            name_len = struct.unpack("!H", data[offset + 1 : offset + 3])[0]
            offset += 3
            if name_type == 0:  # host_name
                host_bytes = data[offset : offset + name_len]
                return host_bytes.decode("ascii", errors="replace").lower()
            offset += name_len
    except Exception:
        pass
    return None


def _parse_alpn(data: bytes) -> list[str]:
    res = []
    try:
        if len(data) < 2:
            return res
        list_len = struct.unpack("!H", data[:2])[0]
        offset = 2
        while offset < len(data):
            proto_len = data[offset]
            offset += 1
            if offset + proto_len <= len(data):
                p_str = data[offset : offset + proto_len].decode("ascii", errors="replace")
                res.append(p_str)
                offset += proto_len
            else:
                break
    except Exception:
        pass
    return res


def _parse_supported_versions(data: bytes) -> list[int]:
    res = []
    try:
        if len(data) < 1:
            return res
        v_len = data[0]
        offset = 1
        while offset + 2 <= len(data):
            v = struct.unpack("!H", data[offset : offset + 2])[0]
            if not is_grease(v):
                res.append(v)
            offset += 2
    except Exception:
        pass
    return res


def compute_ja4(
    protocol: str,
    tls_version: int,
    has_sni: bool,
    ciphers: list[int],
    extensions: list[int],
    alpn: list[str],
) -> str:
    """Compute JA4 fingerprint string.

    Format: {protocol}{version}{has_sni}{num_ciphers:02d}{num_exts:02d}{alpn_first}_{ciphers_hash}_{exts_hash}
    """
    # Version representation: 1.3 -> 13, 1.2 -> 12, 1.1 -> 11, 1.0 -> 10, other -> 00
    ver_str = "00"
    if tls_version == 0x0304:
        ver_str = "13"
    elif tls_version == 0x0303:
        ver_str = "12"
    elif tls_version == 0x0302:
        ver_str = "11"
    elif tls_version == 0x0301:
        ver_str = "10"

    sni_char = "d" if has_sni else "i"  # d = domain, i = ip/none
    num_ciphers = min(99, len(ciphers))
    num_exts = min(99, len(extensions))

    first_alpn = "00"
    if alpn:
        clean_alpn = alpn[0].strip()
        if len(clean_alpn) >= 2:
            first_alpn = clean_alpn[:2]
        elif len(clean_alpn) == 1:
            first_alpn = clean_alpn + "0"

    part_a = f"{protocol}{ver_str}{sni_char}{num_ciphers:02d}{num_exts:02d}{first_alpn}"

    # Cipher hash: hex cipher strings sorted, joined with comma
    ciphers_sorted = sorted(f"{c:04x}" for c in ciphers)
    ciphers_str = ",".join(ciphers_sorted)
    part_b = hashlib.sha256(ciphers_str.encode("utf-8")).hexdigest()[:12]

    # Extensions hash: hex extension strings sorted, joined with comma
    exts_sorted = sorted(f"{e:04x}" for e in extensions)
    exts_str = ",".join(exts_sorted)
    part_c = hashlib.sha256(exts_str.encode("utf-8")).hexdigest()[:12]

    return f"{part_a}_{part_b}_{part_c}"
