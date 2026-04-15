---
title: Security and non-goals
description: The intended security boundary of the honest-majority voting flow.
sidebar:
  order: 6
---

`threshold-elgamal` is a hardened research prototype for browser-native `ristretto255` voting workflows. It provides additive ElGamal, honest-majority GJKR transcript verification, transport helpers, protocol builders, `ballot-close`, and full ceremony verification. It is not audited production voting software.

## What the library tries to guarantee

- Group and scalar inputs are validated before secret-dependent operations.
- The tally path is additive-only.
- The public manifest is minimal and the threshold is derived internally from the accepted registration roster.
- Ballot verification is statement-bound to the manifest hash, session id, voter slot, and option slot.
- Decryption shares are checked against transcript-derived trustee keys and locally recomputed aggregates.
- `ballot-close` makes the counted voter set explicit and auditable on the board.
- The full verifier replays the public ceremony end to end instead of trusting a server-supplied tally.

## What the library does not guarantee by itself

- It does not make JavaScript `bigint` arithmetic constant-time.
- It does not make ElGamal IND-CCA secure.
- It does not prevent a modified client from misusing locally held shares outside the supported workflow.
- It does not provide coercion resistance, receipt-freeness, or cast-as-intended guarantees against a compromised client.
- It does not replace application-level identity binding, bulletin-board storage, delivery hardening, or mobile lifecycle orchestration.

## What callers still need to do

- Bind real users to the registration roster outside the library.
- Recompute public aggregates locally or call the full verifier that does this for you.
- Verify signatures and proofs before trusting any public payloads.
- Treat exact small-group tallies as privacy-sensitive even when the cryptography is correct.
- Treat `ballot-close` as an auditable administrative cutoff, not as proof that the organizer waited long enough before closing.

## Scope boundary

The intended model is honest-origin, honest-client, and static adversary. If the server can deliver malicious JavaScript to the browser, the cryptographic guarantees are gone regardless of how carefully the protocol payloads are verified afterward.

For a production-threat-model verdict that maps these limits onto the verifier and test suite, read [Production voting safety review](./production-voting-safety-review/).
