---
title: Security and non-goals
description: The intended security boundary of the library and the guarantees it does not claim.
sidebar:
  order: 6
---

`threshold-elgamal` is a hardened research prototype for browser-native Ristretto255 ElGamal workflows. It ships careful validation, additive-only root exports, threshold helpers, transport primitives, board-audit helpers, and log-driven DKG reducers. Internal proof and VSS components support those workflows, but they are not separate supported import surfaces. It is not audited production voting software.

Its intended security boundary is still an honest-origin, honest-client, static-adversary model. The shipped distributed workflow now functionally accepts any reconstruction threshold `1 <= k <= n` for ceremonies with `n >= 3`, including `n of n`, but the library does not claim a new malicious-security proof beyond the classical GJKR literature for `t < n / 2`.

## What the library tries to guarantee

- Group and scalar inputs are validated before secret-dependent operations.
- The root package exposes additive ElGamal only.
- Threshold decryption helpers carry participant indices explicitly and reject malformed or duplicate share sets.
- Internal proof components bind protocol version, suite, manifest hash, session id, and any participant- or ballot-specific context you supply.
- Transport envelopes authenticate context through HKDF info and AES-GCM additional data.
- Checkpointed DKG transcripts close each setup phase on a threshold-supported snapshot hash, so clients can compare the same board view before progressing.
- DKG transcript verification rejects qualified Feldman commitment sets whose aggregate highest-degree coefficient collapses to the identity, so the accepted transcript preserves the claimed exact reconstruction threshold.
- The root package can recompute ballot aggregates locally and verify one published tally per option from signed ballot, decryption-share, and tally payloads.
- The root package can audit bulletin-board consistency, distinguish idempotent retransmission from equivocation, and expose stable ceremony digests and fingerprints.

## What the library does not guarantee by itself

- It does not make JavaScript `bigint` arithmetic constant-time.
- It does not turn ElGamal into an IND-CCA-secure scheme.
- It does not prevent a modified client from misusing locally held threshold shares outside the supported workflow.
- It does not provide coercion resistance, receipt-freeness, or cast-as-intended guarantees.
- It does not replace application-level identity binding, bulletin-board storage, or deployment hardening.

## What callers still need to do

- Validate every public transcript input against the intended ceremony context.
- Recompute aggregates locally instead of trusting server-provided aggregates, or call the shipped published-tally verifier that does this for you.
- Verify all proofs and signatures before accepting ciphertexts or decryption shares.
- Treat `minimumPublishedVoterCount` as a tally-publication privacy floor. It is not the DKG reconstruction threshold, and its default `min(k + 1, n)` is an application privacy heuristic rather than a new DKG theorem.
- Keep threshold shares and transport keys in the narrowest possible storage scope.
- Treat small-group exact tallies as potentially privacy-sensitive even when the cryptography is correct.
- Treat the current DKG path as a thesis-scale research workflow. The recommended default size today is `10` all-equal participants. Larger symmetric ceremonies remain experimental.
