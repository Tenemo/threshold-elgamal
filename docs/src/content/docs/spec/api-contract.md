---
title: API contract
description: The hard boundary between shipped library responsibilities and surrounding application responsibilities.
sidebar:
  order: 2
---

The current package draws a hard boundary between the shipped cryptographic library and the surrounding application.

## Library responsibilities

- The minimal public manifest with `rosterHash` and `optionList`
- Honest-majority threshold derivation from the accepted registration roster
- Typed payload builders for manifest publication, registration, acceptance, DKG messages, ballots, ballot close, decryption shares, and tally publication
- Transport and authentication helpers used by the shipped ceremony flow
- Ristretto255-based ballot encryption, proof generation, threshold share handling, and tally recovery helpers
- GJKR transcript verification over the signed public log
- Organizer-signed `ballot-close` verification and counted-ballot selection
- Full-ceremony verification that replays the DKG transcript, recomputes the counted ballot aggregates locally, verifies decryption-share proofs, checks tally publications, and returns board-audit metadata

## Application responsibilities

- Bulletin-board storage and deployment-specific transport plumbing
- UI, orchestration, retries, worker usage, and deadline handling
- Enrollment policy and roster governance before manifest publication
- Pre-DKG vote collection, local plaintext staging, reminders, and organizer controls
- Final application decisions about when the organizer closes voting
- Result presentation and any fairness policy beyond the auditable counted-ballot set
