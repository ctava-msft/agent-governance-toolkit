# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Keyed provenance certificates for governed learning artifacts."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from typing import Any

_ALGORITHM = "hmac-sha256"
_PROCESS_KEY = secrets.token_bytes(32)


def resolve_provenance_key(value: bytes | str | None) -> bytes:
    """Return a validated key, using an ephemeral process key when omitted."""
    if value is None:
        return _PROCESS_KEY
    if isinstance(value, str):
        key = value.encode("utf-8")
    elif isinstance(value, bytes):
        key = value
    else:
        raise TypeError("provenance_key must be bytes, a string, or None")
    if len(key) < 32:
        raise ValueError("provenance_key must contain at least 32 bytes")
    return key


def sign_decision_certificate(
    certificate: Mapping[str, Any],
    key: bytes,
) -> dict[str, Any]:
    unsigned = {name: value for name, value in certificate.items() if name != "provenance"}
    signed = dict(unsigned)
    signed["provenance"] = _sign(key, "decision", unsigned)
    return signed


def verify_decision_certificate(
    certificate: Mapping[str, Any],
    key: bytes,
) -> bool:
    provenance = certificate.get("provenance")
    if not isinstance(provenance, Mapping):
        return False
    unsigned = {name: value for name, value in certificate.items() if name != "provenance"}
    return _verify(key, "decision", unsigned, provenance)


def candidate_payload(policy: Any) -> dict[str, Any]:
    metadata = getattr(policy, "metadata", {}) or {}
    namespace = metadata.get("agent_governance", {}) if isinstance(metadata, Mapping) else {}
    lineage = namespace.get("lineage", {}) if isinstance(namespace, Mapping) else {}
    policy_metadata = (
        {name: value for name, value in metadata.items() if name != "agent_governance"}
        if isinstance(metadata, Mapping)
        else {}
    )
    return {
        "id": policy.id,
        "agent_id": policy.agent_id,
        "task_id": policy.task_id,
        "version": policy.version,
        "actions": [
            {
                "id": action.id,
                "description": getattr(action, "description", None),
                "parameters": dict(getattr(action, "parameters", {}) or {}),
            }
            for action in policy.actions
        ],
        "logits": dict(getattr(policy, "logits", {}) or {}),
        "baseline": getattr(policy, "baseline", None),
        "episodes_seen": getattr(policy, "episodes_seen", None),
        "updates_applied": getattr(policy, "updates_applied", None),
        "metadata": policy_metadata,
        "lineage": dict(lineage) if isinstance(lineage, Mapping) else {},
    }


def candidate_provenance(policy: Any, key: bytes) -> dict[str, str]:
    return _sign(key, "candidate", candidate_payload(policy))


def verify_candidate(policy: Any, key: bytes) -> bool:
    metadata = getattr(policy, "metadata", {}) or {}
    namespace = metadata.get("agent_governance", {}) if isinstance(metadata, Mapping) else {}
    provenance = namespace.get("candidate_provenance") if isinstance(namespace, Mapping) else None
    return isinstance(provenance, Mapping) and _verify(
        key,
        "candidate",
        candidate_payload(policy),
        provenance,
    )


def sign_promotion_receipt(
    policy: Any,
    entry: Mapping[str, Any],
    key: bytes,
) -> dict[str, str]:
    return _sign(key, "promotion", _promotion_payload(policy, entry))


def verify_promotion_receipt(
    policy: Any,
    entry: Mapping[str, Any],
    key: bytes,
) -> bool:
    receipt = entry.get("receipt")
    return isinstance(receipt, Mapping) and _verify(
        key,
        "promotion",
        _promotion_payload(policy, entry),
        receipt,
    )


def _promotion_payload(policy: Any, entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "candidate": candidate_payload(policy),
        "stage": entry.get("stage"),
        "status": entry.get("status"),
        "reason": entry.get("reason"),
        "timestamp": entry.get("timestamp"),
        "validation_passed": entry.get("validation_passed"),
    }


def _sign(key: bytes, purpose: str, payload: Mapping[str, Any]) -> dict[str, str]:
    signature = hmac.new(key, _canonical(purpose, payload), hashlib.sha256).hexdigest()
    return {"algorithm": _ALGORITHM, "signature": signature}


def _verify(
    key: bytes,
    purpose: str,
    payload: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> bool:
    if provenance.get("algorithm") != _ALGORITHM:
        return False
    signature = provenance.get("signature")
    if not isinstance(signature, str):
        return False
    expected = hmac.new(key, _canonical(purpose, payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def _canonical(purpose: str, payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        {"purpose": purpose, "payload": payload},
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


__all__ = [
    "candidate_provenance",
    "resolve_provenance_key",
    "sign_decision_certificate",
    "sign_promotion_receipt",
    "verify_candidate",
    "verify_decision_certificate",
    "verify_promotion_receipt",
]
