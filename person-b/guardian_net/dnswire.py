"""Pure Python standard-library DNS wire-format parser and serializer.

Supports:
- RFC 1035 wire format parsing & serialization
- Record types: A, AAAA, CNAME, TXT, NULL, PTR, NS, MX, SOA, OPT (EDNS0), generic
- DNS compression pointers with strict loop guard and jump bounds
- Safe parsing that rejects truncated or malformed packets without crashing
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any

# Standard DNS Type constants
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_NULL = 10
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_OPT = 41
TYPE_ANY = 255

TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_SOA: "SOA",
    TYPE_NULL: "NULL",
    TYPE_PTR: "PTR",
    TYPE_MX: "MX",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_OPT: "OPT",
    TYPE_ANY: "ANY",
}
NAME_TO_TYPE = {v: k for k, v in TYPE_NAMES.items()}

# Classes
CLASS_IN = 1
CLASS_ANY = 255

# RCODEs
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

MAX_POINTER_HOPS = 16
MAX_NAME_LEN = 255
MAX_LABEL_LEN = 63


class DNSWireError(Exception):
    """Raised when wire parsing fails due to malformed or invalid data."""
    pass


class DNSTruncatedError(DNSWireError):
    """Raised when wire data is unexpectedly truncated."""
    pass


@dataclass
class DNSHeader:
    id: int = 0
    qr: int = 0         # 0 = query, 1 = response
    opcode: int = 0     # 0 = QUERY, etc.
    aa: int = 0         # Authoritative Answer
    tc: int = 0         # TrunCation
    rd: int = 1         # Recursion Desired
    ra: int = 0         # Recursion Available
    z: int = 0          # Reserved
    rcode: int = 0      # Response Code
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    @classmethod
    def parse(cls, data: bytes) -> tuple[DNSHeader, int]:
        if len(data) < 12:
            raise DNSTruncatedError("DNS header is less than 12 bytes")
        msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        qr = (flags >> 15) & 0x01
        opcode = (flags >> 11) & 0x0F
        aa = (flags >> 10) & 0x01
        tc = (flags >> 9) & 0x01
        rd = (flags >> 8) & 0x01
        ra = (flags >> 7) & 0x01
        z = (flags >> 4) & 0x07
        rcode = flags & 0x0F
        return cls(
            id=msg_id,
            qr=qr,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            z=z,
            rcode=rcode,
            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount,
        ), 12

    def to_wire(self) -> bytes:
        flags = (
            ((self.qr & 0x01) << 15)
            | ((self.opcode & 0x0F) << 11)
            | ((self.aa & 0x01) << 10)
            | ((self.tc & 0x01) << 9)
            | ((self.rd & 0x01) << 8)
            | ((self.ra & 0x01) << 7)
            | ((self.z & 0x07) << 4)
            | (self.rcode & 0x0F)
        )
        return struct.pack(
            "!HHHHHH",
            self.id & 0xFFFF,
            flags,
            self.qdcount & 0xFFFF,
            self.ancount & 0xFFFF,
            self.nscount & 0xFFFF,
            self.arcount & 0xFFFF,
        )


@dataclass
class DNSQuestion:
    name: str
    qtype: int
    qclass: int = CLASS_IN

    @property
    def qtype_name(self) -> str:
        return TYPE_NAMES.get(self.qtype, f"TYPE{self.qtype}")

    def to_wire(self, compression: dict[str, int] | None = None) -> bytes:
        wire_name = encode_domain_name(self.name, compression=compression)
        return wire_name + struct.pack("!HH", self.qtype, self.qclass)


@dataclass
class DNSResourceRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: Any  # Parsed representation (IP str, domain str, list of strings, or bytes)
    raw_rdata: bytes = field(default=b"", repr=False)

    @property
    def rtype_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")

    def to_wire(self, compression: dict[str, int] | None = None) -> bytes:
        wire_name = encode_domain_name(self.name, compression=compression)
        raw = self.raw_rdata
        if not raw:
            raw = encode_rdata(self.rtype, self.rdata, compression=compression)
        return wire_name + struct.pack("!HHIH", self.rtype, self.rclass, self.ttl, len(raw)) + raw


@dataclass
class DNSMessage:
    header: DNSHeader = field(default_factory=DNSHeader)
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSResourceRecord] = field(default_factory=list)
    authorities: list[DNSResourceRecord] = field(default_factory=list)
    additionals: list[DNSResourceRecord] = field(default_factory=list)

    @property
    def id(self) -> int:
        return self.header.id

    @property
    def is_response(self) -> bool:
        return self.header.qr == 1

    @property
    def rcode(self) -> int:
        return self.header.rcode

    @property
    def is_tc(self) -> bool:
        return self.header.tc == 1

    @property
    def first_question_name(self) -> str:
        return self.questions[0].name if self.questions else ""

    @property
    def first_question_type_name(self) -> str:
        return self.questions[0].qtype_name if self.questions else ""

    @classmethod
    def parse(cls, data: bytes) -> DNSMessage:
        """Parse raw DNS wire packet into DNSMessage with safety checks."""
        header, offset = DNSHeader.parse(data)
        questions: list[DNSQuestion] = []
        for _ in range(header.qdcount):
            q, offset = parse_question(data, offset)
            questions.append(q)

        answers: list[DNSResourceRecord] = []
        for _ in range(header.ancount):
            rr, offset = parse_resource_record(data, offset)
            answers.append(rr)

        authorities: list[DNSResourceRecord] = []
        for _ in range(header.nscount):
            rr, offset = parse_resource_record(data, offset)
            authorities.append(rr)

        additionals: list[DNSResourceRecord] = []
        for _ in range(header.arcount):
            rr, offset = parse_resource_record(data, offset)
            additionals.append(rr)

        return cls(
            header=header,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
        )

    def to_wire(self) -> bytes:
        """Serialize DNSMessage to wire bytes."""
        # Update header counts
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        self.header.nscount = len(self.authorities)
        self.header.arcount = len(self.additionals)

        body = bytearray()
        # To avoid corrupting offsets with header, serialize questions and RRs
        # Simple compression dictionary mapping name -> offset
        compression: dict[str, int] = {}
        header_wire = self.header.to_wire()
        
        # We start building the packet
        packet = bytearray(header_wire)
        for q in self.questions:
            # We can track compression offset relative to packet start
            packet.extend(q.to_wire())
        for a in self.answers:
            packet.extend(a.to_wire())
        for ns in self.authorities:
            packet.extend(ns.to_wire())
        for ar in self.additionals:
            packet.extend(ar.to_wire())
        return bytes(packet)


def decode_domain_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode domain name from wire format with pointer loop protection.

    Returns:
        tuple[str, int]: (canonical lowercase domain name, next offset after the name)
    """
    labels: list[str] = []
    original_offset = offset
    hops = 0
    jumped = False
    next_offset = -1
    visited_pointers: set[int] = set()

    data_len = len(data)
    while True:
        if offset >= data_len:
            raise DNSTruncatedError(f"Unexpected end of data reading name at offset {offset}")

        length = data[offset]

        # Compression pointer: 2 most significant bits are 11 (0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= data_len:
                raise DNSTruncatedError(f"Truncated pointer at offset {offset}")
            pointer_offset = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True

            hops += 1
            if hops > MAX_POINTER_HOPS:
                raise DNSWireError(f"Exceeded max pointer hops ({MAX_POINTER_HOPS})")

            if pointer_offset in visited_pointers:
                raise DNSWireError(f"Circular compression pointer detected to offset {pointer_offset}")
            visited_pointers.add(pointer_offset)

            if pointer_offset >= data_len:
                raise DNSWireError(f"Pointer points outside message bounds: {pointer_offset} >= {data_len}")

            offset = pointer_offset
            continue

        # Normal label
        if (length & 0xC0) != 0:
            raise DNSWireError(f"Invalid label type byte 0x{length:02x} at offset {offset}")

        offset += 1
        if length == 0:
            # End of name (root label)
            break

        if length > MAX_LABEL_LEN:
            raise DNSWireError(f"Label length {length} exceeds maximum {MAX_LABEL_LEN}")

        if offset + length > data_len:
            raise DNSTruncatedError(f"Label data extends past buffer: {offset} + {length} > {data_len}")

        label_bytes = data[offset : offset + length]
        try:
            label_str = label_bytes.decode("ascii")
        except UnicodeDecodeError:
            # Fallback to escaped string or latin-1 to avoid crash
            label_str = label_bytes.decode("latin-1", errors="replace")
        labels.append(label_str)
        offset += length

    if not jumped:
        next_offset = offset

    domain = ".".join(labels).lower()
    if len(domain) > MAX_NAME_LEN:
        raise DNSWireError(f"Domain name length {len(domain)} exceeds maximum {MAX_NAME_LEN}")

    return domain, next_offset


def encode_domain_name(domain: str, compression: dict[str, int] | None = None) -> bytes:
    """Encode domain name into wire format with label length validation."""
    clean = domain.strip().strip(".")
    if not clean:
        return b"\x00"

    parts = clean.split(".")
    encoded = bytearray()
    for part in parts:
        b_part = part.encode("ascii")
        if len(b_part) > MAX_LABEL_LEN:
            raise DNSWireError(f"Label '{part}' exceeds {MAX_LABEL_LEN} bytes")
        encoded.append(len(b_part))
        encoded.extend(b_part)
    encoded.append(0)
    if len(encoded) > MAX_NAME_LEN:
        raise DNSWireError(f"Encoded domain name exceeds {MAX_NAME_LEN} bytes")
    return bytes(encoded)


def parse_question(data: bytes, offset: int) -> tuple[DNSQuestion, int]:
    name, offset = decode_domain_name(data, offset)
    if offset + 4 > len(data):
        raise DNSTruncatedError("Truncated question section")
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    return DNSQuestion(name=name, qtype=qtype, qclass=qclass), offset + 4


def parse_resource_record(data: bytes, offset: int) -> tuple[DNSResourceRecord, int]:
    name, offset = decode_domain_name(data, offset)
    if offset + 10 > len(data):
        raise DNSTruncatedError("Truncated RR header")
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
    offset += 10

    if offset + rdlength > len(data):
        raise DNSTruncatedError(f"RR data truncated: need {rdlength} bytes at {offset}, got {len(data) - offset}")

    raw_rdata = data[offset : offset + rdlength]
    end_offset = offset + rdlength

    parsed_rdata: Any = raw_rdata
    try:
        if rtype == TYPE_A:
            if rdlength == 4:
                parsed_rdata = socket.inet_ntoa(raw_rdata)
        elif rtype == TYPE_AAAA:
            if rdlength == 16:
                parsed_rdata = socket.inet_ntop(socket.AF_INET6, raw_rdata)
        elif rtype in (TYPE_CNAME, TYPE_PTR, TYPE_NS):
            parsed_rdata, _ = decode_domain_name(data, offset)
        elif rtype == TYPE_TXT:
            # Parse sequence of <character-string>
            txts = []
            cur = 0
            while cur < rdlength:
                tlen = raw_rdata[cur]
                cur += 1
                txt_bytes = raw_rdata[cur : cur + tlen]
                txts.append(txt_bytes.decode("utf-8", errors="replace"))
                cur += tlen
            parsed_rdata = txts
        elif rtype == TYPE_NULL:
            parsed_rdata = raw_rdata
        elif rtype == TYPE_MX:
            if rdlength >= 3:
                preference = struct.unpack("!H", raw_rdata[:2])[0]
                exchange, _ = decode_domain_name(data, offset + 2)
                parsed_rdata = (preference, exchange)
        elif rtype == TYPE_SOA:
            mname, m_off = decode_domain_name(data, offset)
            rname, r_off = decode_domain_name(data, m_off)
            if r_off + 20 <= end_offset:
                serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[r_off : r_off + 20])
                parsed_rdata = {
                    "mname": mname,
                    "rname": rname,
                    "serial": serial,
                    "refresh": refresh,
                    "retry": retry,
                    "expire": expire,
                    "minimum": minimum,
                }
    except Exception:
        # If parsing specific rdata fails, keep raw_rdata without crashing
        parsed_rdata = raw_rdata

    return DNSResourceRecord(
        name=name,
        rtype=rtype,
        rclass=rclass,
        ttl=ttl,
        rdata=parsed_rdata,
        raw_rdata=raw_rdata,
    ), end_offset


def encode_rdata(rtype: int, rdata: Any, compression: dict[str, int] | None = None) -> bytes:
    if isinstance(rdata, bytes):
        return rdata
    if rtype == TYPE_A:
        return socket.inet_aton(str(rdata))
    if rtype == TYPE_AAAA:
        return socket.inet_pton(socket.AF_INET6, str(rdata))
    if rtype in (TYPE_CNAME, TYPE_PTR, TYPE_NS):
        return encode_domain_name(str(rdata), compression=compression)
    if rtype == TYPE_TXT:
        if isinstance(rdata, str):
            rdata = [rdata]
        out = bytearray()
        for item in rdata:
            b_item = item.encode("utf-8") if isinstance(item, str) else bytes(item)
            out.append(min(len(b_item), 255))
            out.extend(b_item[:255])
        return bytes(out)
    return str(rdata).encode("utf-8")


def make_query(name: str, qtype: int = TYPE_A, msg_id: int | None = None) -> DNSMessage:
    """Helper to create a standard recursive query."""
    if msg_id is None:
        import os
        msg_id = int.from_bytes(os.urandom(2), "big")
    header = DNSHeader(id=msg_id, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, rcode=0, qdcount=1)
    question = DNSQuestion(name=name, qtype=qtype, qclass=CLASS_IN)
    return DNSMessage(header=header, questions=[question])


def make_response(
    query: DNSMessage,
    rcode: int = RCODE_NOERROR,
    answers: list[DNSResourceRecord] | None = None,
    authorities: list[DNSResourceRecord] | None = None,
    additionals: list[DNSResourceRecord] | None = None,
) -> DNSMessage:
    """Helper to create a response matching a query."""
    header = DNSHeader(
        id=query.header.id,
        qr=1,
        opcode=query.header.opcode,
        aa=1,
        tc=0,
        rd=query.header.rd,
        ra=1,
        rcode=rcode,
        qdcount=len(query.questions),
        ancount=len(answers or []),
        nscount=len(authorities or []),
        arcount=len(additionals or []),
    )
    return DNSMessage(
        header=header,
        questions=list(query.questions),
        answers=list(answers or []),
        authorities=list(authorities or []),
        additionals=list(additionals or []),
    )
