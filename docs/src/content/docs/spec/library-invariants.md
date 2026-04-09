---
title: Library invariants
description: Stable rules for the shipped cryptographic surface, encoding, threshold behavior, and documentation generation.
sidebar:
  order: 1
---

This page records the stable invariants of the current 1.x surface.

## Cryptographic surface

- The safe root package remains additive-only.
- Raw multiplicative mode is not part of the shipped public API.
- Built-in groups are the frozen RFC 7919 FFDHE suites `ffdhe2048`, `ffdhe3072`, and `ffdhe4096`.
- Each built-in group includes `p`, `q`, `g`, and a deterministic secondary generator `h`.

## Validation and encoding

- External group elements that interact with secret exponents must pass subgroup validation.
- Scalars intended for `Z_q` arithmetic are validated against the selected group order.
- Fiat-Shamir challenge encoding is injective.
- Variable-length transcript sequences are count-prefixed before element encoding.
- Canonical protocol payload bytes are derived from RFC 8785-style canonical JSON with fixed-width bigint hex encoding.

## Threshold and protocol rules

- Dealer threshold helpers operate on indexed Shamir shares with 1-based participant indices.
- The public threshold surface combines only additive ElGamal ciphertexts.
- Safe aggregate decryption helpers require a verified aggregate context with a non-empty transcript hash.
- DKG reducers are pure log-driven state machines with deterministic replay from signed payloads.
- Protocol payload idempotence and equivocation checks are defined over unsigned canonical payload bytes.

## Documentation scope

- The generated API reference is export-driven from `package.json`.
- Documentation-generation tooling lives under the top-level `typedoc/` directory.
- Development-only wrappers that write fixtures or run reproducibility checks may remain outside `src/`, but reusable logic belongs alongside the relevant library module inside `src/`.
