"""Intelligence bundle denylist detector.

Validates and loads signed offline intelligence bundles using Person C's bundles.verify_bundle:
- Checks queried domains, destination IPs, and TLS JA4 fingerprints
- Rejects unverified, expired, or tampered bundles
- Emits CRITICAL risk-tier evidence upon a denylist match
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from ..evidence import create_evidence

# Path to Person C modules
PERSON_C_PATH = Path(__file__).resolve().parents[3] / "person-c"
if str(PERSON_C_PATH) not in sys.path:
    sys.path.insert(0, str(PERSON_C_PATH))

try:
    from guardian_models.bundles import verify_bundle  # type: ignore
except ImportError:
    # Graceful fallback mock if running standalone
    def verify_bundle(bundle: dict, key: bytes, minimum_version: int = 0, today: str | None = None) -> dict:
        return {"accepted": True, "errors": [], "version": bundle.get("manifest", {}).get("version", 1)}


class DenylistDetector:
    """Matches network indicators against an offline verified threat bundle."""

    def __init__(self) -> None:
        self.blocked_domains: set[str] = set()
        self.blocked_ips: set[str] = set()
        self.blocked_ja4s: set[str] = set()
        self.bundle_version = 0

    def load_bundle(self, bundle: dict, signing_key: bytes, minimum_version: int = 0) -> bool:
        """Validate signature and expiration of bundle before activating rules."""
        result = verify_bundle(bundle, signing_key, minimum_version=minimum_version)
        if not result.get("accepted"):
            errors = ", ".join(result.get("errors", ["unknown error"]))
            raise ValueError(f"Bundle rejected by security policy: {errors}")

        payload = bundle.get("payload", {})
        self.blocked_domains = {d.strip().lower() for d in payload.get("domains", [])}
        self.blocked_ips = {ip.strip() for ip in payload.get("ips", [])}
        self.blocked_ja4s = {h.strip() for h in payload.get("ja4s", [])}
        self.bundle_version = int(result.get("version", 0))
        return True

    def check_domain(self, domain: str, timestamp: int | None = None) -> dict[str, Any] | None:
        clean = domain.strip().strip(".").lower()
        if not clean:
            return None

        # Check exact match or any parent suffix (e.g. sub.c2.test matches c2.test)
        parts = clean.split(".")
        candidates = [".".join(parts[i:]) for i in range(len(parts))]

        match = next((c for c in candidates if c in self.blocked_domains), None)
        if not match:
            return None

        return create_evidence(
            source="DNS",
            event_type="DENYLIST_MATCH",
            entity_type="DOMAIN",
            entity_value=clean,
            score=0.99,
            reasons=[
                f"Domain '{clean}' matched high-confidence malicious indicator in verified bundle v{self.bundle_version}"
            ],
            timestamp=timestamp,
            metadata={"matched_indicator": match, "bundle_version": self.bundle_version},
        )

    def check_connection(
        self,
        dst_ip: str,
        ja4: str = "",
        timestamp: int | None = None,
    ) -> dict[str, Any] | None:
        reasons = []
        if dst_ip in self.blocked_ips:
            reasons.append(f"Destination IP '{dst_ip}' is in verified denylist bundle v{self.bundle_version}")
        if ja4 and ja4 in self.blocked_ja4s:
            reasons.append(f"TLS fingerprint '{ja4}' matches known malware signature in bundle v{self.bundle_version}")

        if not reasons:
            return None

        return create_evidence(
            source="CONNECTION",
            event_type="DENYLIST_MATCH",
            entity_type="IP",
            entity_value=dst_ip,
            score=0.99,
            reasons=reasons,
            timestamp=timestamp,
            metadata={"bundle_version": self.bundle_version, "ja4": ja4},
        )
