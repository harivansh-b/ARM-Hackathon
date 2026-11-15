"""Unit tests for DNS wire-format parser and serializer."""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.dnswire import (
    DNSHeader,
    DNSMessage,
    DNSQuestion,
    DNSResourceRecord,
    DNSTruncatedError,
    DNSWireError,
    RCODE_NXDOMAIN,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_NULL,
    TYPE_TXT,
    decode_domain_name,
    encode_domain_name,
    make_query,
    make_response,
)


class TestDNSWire(unittest.TestCase):
    def test_encode_decode_domain_name(self) -> None:
        raw = encode_domain_name("sub.example.com")
        self.assertEqual(raw, b"\x03sub\x07example\x03com\x00")
        name, offset = decode_domain_name(raw, 0)
        self.assertEqual(name, "sub.example.com")
        self.assertEqual(offset, len(raw))

    def test_root_domain_name(self) -> None:
        raw = encode_domain_name(".")
        self.assertEqual(raw, b"\x00")
        name, offset = decode_domain_name(raw, 0)
        self.assertEqual(name, "")
        self.assertEqual(offset, 1)

    def test_query_round_trip(self) -> None:
        q = make_query("api.guardian.test", TYPE_A, msg_id=0x1234)
        wire = q.to_wire()
        parsed = DNSMessage.parse(wire)
        self.assertEqual(parsed.id, 0x1234)
        self.assertEqual(parsed.header.qr, 0)
        self.assertEqual(len(parsed.questions), 1)
        self.assertEqual(parsed.questions[0].name, "api.guardian.test")
        self.assertEqual(parsed.questions[0].qtype, TYPE_A)

    def test_response_round_trip_a_and_cname(self) -> None:
        q = make_query("www.example.com", TYPE_A, msg_id=0xCAFE)
        cname_rr = DNSResourceRecord(
            name="www.example.com",
            rtype=TYPE_CNAME,
            rclass=1,
            ttl=300,
            rdata="example.com",
        )
        a_rr = DNSResourceRecord(
            name="example.com",
            rtype=TYPE_A,
            rclass=1,
            ttl=300,
            rdata="93.184.216.34",
        )
        resp = make_response(q, answers=[cname_rr, a_rr])
        wire = resp.to_wire()
        parsed = DNSMessage.parse(wire)
        self.assertEqual(parsed.id, 0xCAFE)
        self.assertEqual(parsed.header.qr, 1)
        self.assertEqual(len(parsed.answers), 2)
        self.assertEqual(parsed.answers[0].rdata, "example.com")
        self.assertEqual(parsed.answers[1].rdata, "93.184.216.34")

    def test_response_aaaa_txt_null(self) -> None:
        q = make_query("test.corp", TYPE_TXT, msg_id=0x5678)
        aaaa_rr = DNSResourceRecord("test.corp", TYPE_AAAA, 1, 60, "2001:db8::1")
        txt_rr = DNSResourceRecord("test.corp", TYPE_TXT, 1, 60, ["v=spf1 ~all", "status=ok"])
        null_rr = DNSResourceRecord("test.corp", TYPE_NULL, 1, 60, b"\x01\x02\x03\x04")
        resp = make_response(q, answers=[aaaa_rr, txt_rr, null_rr])
        wire = resp.to_wire()
        parsed = DNSMessage.parse(wire)
        self.assertEqual(parsed.answers[0].rdata, "2001:db8::1")
        self.assertEqual(parsed.answers[1].rdata, ["v=spf1 ~all", "status=ok"])
        self.assertEqual(parsed.answers[2].rdata, b"\x01\x02\x03\x04")

    def test_compression_pointer_valid(self) -> None:
        # Construct packet with compression pointer:
        # At offset 12: \x03com\x00 (com.)
        # At offset 16: \x07example + pointer to offset 12 -> example.com.
        data = bytearray(b"\x00" * 12)  # header
        data.extend(b"\x03com\x00")    # offset 12..16
        data.extend(b"\x07example\xc0\x0c")  # offset 17..
        name, offset = decode_domain_name(data, 17)
        self.assertEqual(name, "example.com")
        self.assertEqual(offset, 17 + 8 + 2)

    def test_compression_pointer_circular_loop(self) -> None:
        # Pointer at offset 12 pointing to offset 14, and offset 14 pointing back to 12
        data = bytearray(b"\x00" * 12)
        data.extend(b"\xc0\x0e")  # offset 12: points to 14
        data.extend(b"\xc0\x0c")  # offset 14: points to 12
        with self.assertRaises(DNSWireError) as ctx:
            decode_domain_name(data, 12)
        self.assertIn("Circular compression pointer", str(ctx.exception))

    def test_compression_pointer_self_reference(self) -> None:
        # Pointer at offset 12 pointing to itself (offset 12)
        data = bytearray(b"\x00" * 12)
        data.extend(b"\xc0\x0c")  # points to 12
        with self.assertRaises(DNSWireError) as ctx:
            decode_domain_name(data, 12)
        self.assertIn("Circular compression pointer", str(ctx.exception))

    def test_compression_pointer_out_of_bounds(self) -> None:
        data = bytearray(b"\x00" * 12)
        data.extend(b"\xc0\x99")  # offset 153 out of bounds
        with self.assertRaises(DNSWireError):
            decode_domain_name(data, 12)

    def test_compression_pointer_max_hops(self) -> None:
        # Chain of 20 pointers: each points to the next
        data = bytearray(b"\x00" * 12)
        for i in range(20):
            next_ptr = 12 + (i + 1) * 2
            data.extend(b"\xc0" + bytes([next_ptr]))
        data.extend(b"\x03foo\x00")
        with self.assertRaises(DNSWireError) as ctx:
            decode_domain_name(data, 12)
        self.assertIn("Exceeded max pointer hops", str(ctx.exception))

    def test_truncated_packet_handling(self) -> None:
        # Header too short (< 12 bytes)
        with self.assertRaises(DNSTruncatedError):
            DNSMessage.parse(b"\x00\x01\x02")

        # Question header says 1 question, but data ends
        q_trunc = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        with self.assertRaises(DNSTruncatedError):
            DNSMessage.parse(q_trunc)

        # Incomplete question QTYPE/QCLASS
        q_partial = q_trunc + b"\x07example\x03com\x00\x00"  # missing 3 bytes
        with self.assertRaises(DNSTruncatedError):
            DNSMessage.parse(q_partial)

    def test_fuzz_random_data_does_not_crash(self) -> None:
        # Ensure arbitrary malformed bytes always raise DNSWireError without unhandled crash
        rng = os.urandom
        for _ in range(200):
            bad_data = rng(50)
            try:
                DNSMessage.parse(bad_data)
            except DNSWireError:
                pass  # expected graceful rejection


if __name__ == "__main__":
    unittest.main()
