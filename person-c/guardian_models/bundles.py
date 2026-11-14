"""Offline-signed model/intelligence bundle validation.

The reference implementation uses HMAC-SHA256 so it stays dependency-free.
Production Android distribution should replace the shared secret with an
Ed25519 public-key signature while preserving the manifest fields and checks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import date


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_bundle(payload: dict, key: bytes, version: int, expires: str) -> dict:
    manifest = {"version": version, "expires": expires, "sha256": hashlib.sha256(_canonical(payload)).hexdigest()}
    signature = hmac.new(key, _canonical({"manifest": manifest, "payload": payload}), hashlib.sha256).digest()
    return {"manifest": manifest, "payload": payload, "signature": base64.b64encode(signature).decode()}


def verify_bundle(bundle: dict, key: bytes, minimum_version: int = 0, today: str | None = None) -> dict:
    manifest = bundle.get("manifest", {})
    payload = bundle.get("payload", {})
    expected_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    expected_sig = hmac.new(key, _canonical({"manifest": manifest, "payload": payload}), hashlib.sha256).digest()
    actual_sig = base64.b64decode(bundle.get("signature", ""), validate=True)
    errors = []
    if not hmac.compare_digest(expected_hash, manifest.get("sha256", "")):
        errors.append("payload_hash_mismatch")
    if not hmac.compare_digest(expected_sig, actual_sig):
        errors.append("signature_invalid")
    if int(manifest.get("version", -1)) < minimum_version:
        errors.append("rollback_rejected")
    if (today or date.today().isoformat()) > str(manifest.get("expires", "0000-00-00")):
        errors.append("bundle_expired")
    return {"accepted": not errors, "errors": errors, "version": manifest.get("version")}
