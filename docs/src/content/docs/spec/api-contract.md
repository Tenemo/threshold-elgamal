---
title: API contract
description: The hard boundary between shipped library responsibilities and surrounding application responsibilities.
sidebar:
  order: 2
---

The current package draws a hard boundary between the shipped cryptographic library and the surrounding application.

## Library responsibilities

- Ristretto255 group definitions and scalar arithmetic
- Safe additive ElGamal on the root package
- Ciphertext combination helpers for the shipped additive workflow
- Serialization and deterministic encoding helpers
- Runtime validation for public inputs, plaintext domains, and point validity
- Dealer-based threshold sharing and additive threshold decryption
- Protocol, transport, and log-driven DKG helpers on the supported root package
- Internal VSS and proof components used by the shipped protocol and DKG workflows
- Typed manifest, ballot, decryption-share, tally-publication, and restart payload schemas
- Transcript-native complaint-resolution verification
- Bulletin-board auditing that canonicalizes ordering, classifies duplicate slots, and exposes ceremony digests and fingerprints
- A high-level full-ceremony verifier that replays the DKG transcript, recomputes the accepted ballot aggregates locally, verifies decryption-share proofs, checks per-option tally publications, and validates board consistency

## Application responsibilities

- Bulletin-board storage, deployment-specific transport plumbing, and operational policy
- Tally policy, additive bound selection, arithmetic-mean interpretation, and result presentation
- UI, orchestration, retries, and deadline handling
- Final application decisions about enrollment, trustee workflows, deadlines, retries, and publication timing
