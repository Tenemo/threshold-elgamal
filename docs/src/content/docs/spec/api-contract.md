---
title: API contract
description: The hard boundary between shipped library responsibilities and surrounding application responsibilities.
sidebar:
  order: 2
---

The current package draws a hard boundary between the shipped cryptographic library and the surrounding application.

## Library responsibilities

- Group definitions and scalar arithmetic
- Safe additive ElGamal on the root package
- Ciphertext combination helpers for the shipped additive workflow
- Serialization and deterministic encoding helpers
- Runtime validation for public inputs, plaintext domains, and subgroup membership
- Dealer-based threshold sharing and additive threshold decryption
- Standalone VSS, proof, protocol, transport, and log-driven DKG helpers
- Typed manifest, ballot, decryption-share, tally-publication, and restart
  payload schemas
- Transcript-native complaint-resolution verification
- A high-level published-tally verifier that replays the DKG transcript,
  recomputes the accepted ballot aggregate locally, verifies decryption-share
  proofs, and checks one published tally

## Application responsibilities

- Bulletin-board storage, deployment-specific transport plumbing, and operational policy
- Tally policy, additive bound selection, and result interpretation
- UI, orchestration, retries, and deadline handling
- Final application decisions about enrollment, trustee workflows, deadlines,
  retries, and publication timing
