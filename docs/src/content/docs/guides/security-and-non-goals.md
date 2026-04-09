---
title: Security and non-goals
description: The intended security boundary of the library and the guarantees it does not claim.
sidebar:
  order: 6
---

`threshold-elgamal` is a hardened research prototype for browser-native finite-field ElGamal workflows. It ships careful validation, additive-only root exports, threshold helpers, proofs, transport primitives, and log-driven DKG reducers, but it is not audited production voting software.

Its intended security boundary is still an honest-origin, honest-client,
static-adversary model with a strict-majority threshold policy
`floor(n / 2) + 1 <= k <= n - 1`.

## What the library tries to guarantee

- Group and scalar inputs are validated before secret-dependent operations.
- The root package exposes additive ElGamal only.
- Threshold decryption helpers carry participant indices explicitly and reject malformed or duplicate share sets.
- Proof helpers bind protocol version, suite, manifest hash, session id, and any participant- or ballot-specific context you supply.
- Transport envelopes authenticate context through HKDF info and AES-GCM additional data.
- The protocol subpath can recompute ballot aggregates locally and verify one
  published tally per option from signed ballot, decryption-share, and tally
  payloads.

## What the library does not guarantee by itself

- It does not make JavaScript `bigint` arithmetic constant-time.
- It does not turn ElGamal into an IND-CCA-secure scheme.
- It does not prevent a modified client from misusing locally held threshold shares outside the supported workflow.
- It does not provide coercion resistance, receipt-freeness, or cast-as-intended guarantees.
- It does not replace application-level identity binding, bulletin-board consistency, or deployment hardening.

## What callers still need to do

- Validate every public transcript input against the intended ceremony context.
- Recompute aggregates locally instead of trusting server-provided aggregates,
  or call the shipped published-tally verifier that does this for you.
- Verify all proofs and signatures before accepting ciphertexts or decryption shares.
- Keep threshold shares and transport keys in the narrowest possible storage scope.
- Treat small-group exact tallies as potentially privacy-sensitive even when the cryptography is correct.
- Treat the current DKG path as a thesis-scale research workflow for roughly 50
  all-equal participants, not a thousands-voter symmetric ceremony.
