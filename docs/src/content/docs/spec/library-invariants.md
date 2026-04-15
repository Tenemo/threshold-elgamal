---
title: Library invariants
description: Stable rules for the cryptographic surface and protocol flow.
sidebar:
  order: 1
---

This page records the library invariants.

## Cryptographic surface

- The tally path is additive-only.
- The built-in tally group is `ristretto255`.
- The score domain is fixed to `1..10`.
- The grouped ballot rule is fixed to complete ballots only.
- Conflicting same-slot ballots are treated as equivocation, while byte-identical replays stay idempotent.

## Manifest and threshold rules

- The public manifest shape is only `rosterHash` and `optionList`.
- The accepted registration roster is the authoritative public source of `n`.
- The library derives the threshold internally as `k = ceil(n / 2)`.
- There is no supported public `k-of-n` configuration and no supported `n-of-n` mode.

## Voting and tally rules

- `ballot-close` is mandatory before decryption and tally verification.
- `ballot-close` must be signed by the organizer, defined as the manifest publisher.
- Every included participant in `ballot-close` must have a complete ballot.
- The close-selected participant set must contain at least `k` participants.
- Published tallies are verified against aggregates recomputed from the close-selected ballot set.
- If an accepted aggregate lands on identity `c1`, the reveal path deterministically adds a public encryption of zero before DLEQ proof generation and verification so the plaintext stays unchanged.

## Verification rules

- Protocol payload idempotence and equivocation checks are defined over unsigned canonical payload bytes.
- Board auditing produces per-phase digests, an overall ceremony digest, slot-audit metadata, and a short fingerprint.
- The full verifier replays the DKG transcript, counted ballots, decryption shares, and tally publications from signed public payloads.

## Public payload encoding

- Published protocol payloads are JSON-safe `{ payload, signature }` objects with points, scalars, proofs, and signatures already string-encoded.
