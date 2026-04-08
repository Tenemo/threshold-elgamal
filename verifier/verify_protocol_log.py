#!/usr/bin/env python3
"""Standalone verifier for canonical threshold-elgamal protocol logs.

This verifier is intentionally zero-dependency. It focuses on the bulletin-board
properties that can be checked from the serialized log alone:

- canonical unsigned payload bytes
- deterministic slot-key classification
- idempotence vs. equivocation
- deterministic transcript hashing
- session fingerprint formatting

Usage:
    python verifier/verify_protocol_log.py path/to/log.json
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def canonicalize(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return json.dumps(value)

    if isinstance(value, (int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError("Canonical JSON numbers must be finite")
        return json.dumps(value)

    if isinstance(value, str):
        return json.dumps(value)

    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"

    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(key) + ":" + canonicalize(value[key])
            for key in sorted(value.keys())
        ) + "}"

    raise TypeError(f"Unsupported canonical JSON value: {type(value)!r}")


def payload_slot_key(payload: Dict[str, Any]) -> str:
    return (
        f"{payload['sessionId']}:{payload['phase']}:"
        f"{payload['participantIndex']}:{payload['messageType']}"
    )


def canonical_unsigned_payload_bytes(payload: Dict[str, Any]) -> bytes:
    return canonicalize(payload).encode("utf-8")


def classify_slot_conflict(
    left: Dict[str, Any], right: Dict[str, Any]
) -> str:
    if payload_slot_key(left["payload"]) != payload_slot_key(right["payload"]):
        return "distinct"

    return (
        "idempotent"
        if canonical_unsigned_payload_bytes(left["payload"])
        == canonical_unsigned_payload_bytes(right["payload"])
        else "equivocation"
    )


def sort_payloads(payloads: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        payloads,
        key=lambda item: (
            item["payload"]["sessionId"],
            item["payload"]["phase"],
            item["payload"]["participantIndex"],
            item["payload"]["messageType"],
        ),
    )


def transcript_hash(payloads: Iterable[Dict[str, Any]]) -> str:
    canonical = canonicalize([item["payload"] for item in sort_payloads(payloads)])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def session_fingerprint(transcript_digest: str) -> str:
    digest = transcript_digest[:32].upper()
    return "-".join(digest[index : index + 4] for index in range(0, len(digest), 4))


def find_conflicts(payloads: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    conflicts: List[Tuple[str, str]] = []

    for left_index, left in enumerate(payloads):
        for right in payloads[left_index + 1 :]:
            classification = classify_slot_conflict(left, right)
            if classification != "distinct":
                conflicts.append((payload_slot_key(left["payload"]), classification))

    return conflicts


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python verifier/verify_protocol_log.py path/to/log.json", file=sys.stderr)
        return 1

    path = Path(sys.argv[1])
    payloads = json.loads(path.read_text("utf-8"))
    if not isinstance(payloads, list):
        raise ValueError("The verifier expects a top-level JSON array of signed payloads")

    digest = transcript_hash(payloads)
    conflicts = find_conflicts(payloads)

    print(json.dumps(
        {
            "transcriptHash": digest,
            "sessionFingerprint": session_fingerprint(digest),
            "conflicts": [
                {"slotKey": slot_key, "classification": classification}
                for slot_key, classification in conflicts
            ],
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
