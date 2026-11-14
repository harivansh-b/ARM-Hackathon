"""Deterministic safety controls around advisory language-model output."""

from __future__ import annotations

import re


PLAYBOOK = {
    "credential": "Do not share OTPs, PINs, CVVs, passwords, or verification codes.",
    "link": "Do not open the link; verify the organisation through its official app or website.",
    "payment": "Do not pay a fee or transfer money to claim a reward or resolve an unexpected request.",
    "impersonation": "Contact the organisation using a trusted number or official app, not the message.",
}

UNSAFE_ACTIONS = re.compile(r"\b(click|open|tap|pay|transfer|install|call|send|share|reply)\b", re.I)
REASSURANCE = re.compile(r"\b(safe|legitimate|no risk|harmless|trusted)\b", re.I)


def approved_actions(evidence: dict) -> list[str]:
    signals = {item.get("signal", "") for item in evidence.get("matched_signals", [])}
    actions = []
    if "Sensitive credential request" in signals:
        actions.append(PLAYBOOK["credential"])
    if "Link present" in signals:
        actions.append(PLAYBOOK["link"])
    if "Payment or reward language" in signals:
        actions.append(PLAYBOOK["payment"])
    if "Impersonation context" in signals:
        actions.append(PLAYBOOK["impersonation"])
    return actions or [evidence.get("safe_action", "Verify independently before responding.")]


def verify_explanation(explanation: str, evidence: dict, language: str = "en", max_chars: int = 600) -> dict:
    """Return a pass/fail decision; the explanation cannot change the verdict."""
    reasons = []
    if not explanation or len(explanation) > max_chars:
        reasons.append("empty_or_overlong")
    if evidence.get("risk_tier") in {"HIGH", "CRITICAL"} and REASSURANCE.search(explanation):
        reasons.append("unsafe_reassurance")
    known_entities = set([evidence.get("entity", {}).get("value", "")] + evidence.get("extracted_urls", []))
    for url in re.findall(r"https?://[^\s)]+", explanation):
        if url.rstrip(".,") not in known_entities:
            reasons.append("invented_entity")
            break
    for number in re.findall(r"\+?\d{8,}", explanation):
        if not any(number in str(entity) for entity in known_entities):
            reasons.append("invented_entity")
            break
    if UNSAFE_ACTIONS.search(explanation) and not any(action.lower() in explanation.lower() for action in approved_actions(evidence)):
        reasons.append("unapproved_action")
    if language == "hi" and re.search(r"\b(the|your|click|safe|verify)\b", explanation, re.I):
        reasons.append("language_mismatch")
    return {"accepted": not reasons, "reasons": reasons, "fallback": evidence.get("explanation", evidence.get("safe_action", "Verify independently."))}
