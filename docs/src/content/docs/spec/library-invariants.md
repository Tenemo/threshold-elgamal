---
title: Library invariants
description: Stable rules for the shipped cryptographic surface, encoding, threshold behavior, and documentation generation.
sidebar:
  order: 1
---

This page records the stable invariants of the current `1.0.0-beta` surface.

## Cryptographic surface

- The safe root package remains additive-only.
- Raw multiplicative mode is not part of the shipped public API.
- The shipped built-in tally suite is `ristretto255`.
- The built-in group includes `q`, `g`, a deterministic secondary generator `h`, `byteLength`, and `scalarByteLength`.

## Validation and encoding

- External group elements that interact with secret scalars must pass Ristretto point validation.
- Scalars intended for `Z_q` arithmetic are validated against the selected group order.
- Fiat-Shamir challenge encoding is injective.
- Variable-length transcript sequences are count-prefixed before element encoding.
- Canonical protocol payload bytes are derived from RFC 8785-style canonical JSON with fixed-width lowercase hexadecimal point and scalar encodings.

## Threshold and protocol rules

- Dealer threshold helpers operate on indexed Shamir shares with 1-based participant indices.
- Distributed DKG manifests enforce a strict-majority threshold range `floor(n / 2) + 1 <= k <= n - 1`.
- `minimumPublishedVoterCount` is a ballot-publication privacy floor and is separate from the DKG reconstruction threshold.
- The public threshold surface combines only additive ElGamal ciphertexts.
- Safe aggregate decryption helpers require a verified aggregate context with a non-empty transcript hash.
- Published tally verification recomputes one additive aggregate and one tally per option slot.
- The shipped score-voting protocol surface is fixed to `1..10`, requires exactly one accepted ballot slot per voter per option, and counts distinct accepted voters for publication-floor checks.
- DKG reducers are pure log-driven state machines with deterministic replay from signed payloads.
- Checkpointed DKG transcripts close phases on threshold-supported snapshot hashes rather than unanimous progress.
- Final key-derivation confirmations are advisory in checkpointed DKG transcripts and do not redefine `QUAL`.
- Protocol payload idempotence and equivocation checks are defined over unsigned canonical payload bytes.
- Board auditing produces canonical per-phase digests, an overall ceremony digest, slot-audit metadata, and a short human-readable fingerprint.
- `epochDeadlines` are manifest metadata for application coordination. They are validated for shape but are not yet cryptographically enforced by the verifier.

## Documentation scope

- The generated API reference is export-driven from `package.json`.
- Documentation-generation tooling lives under the top-level `typedoc/` directory.
- Development-only wrappers that write fixtures or run reproducibility checks may remain outside `src/`, but reusable logic belongs alongside the relevant library module inside `src/`.
