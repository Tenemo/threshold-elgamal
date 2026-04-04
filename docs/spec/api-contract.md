# API contract

The v2 rewrite draws a hard boundary between the cryptographic library and the surrounding application.

## Library responsibilities

- Group definitions and scalar arithmetic
- Plain ElGamal and threshold ElGamal primitives
- Proof systems and proof verification
- Typed protocol payloads and validation
- Canonical serialization and transcript hashing
- Envelope cryptography for encrypted share transport
- DKG state-machine transitions and phase-admissibility checks

## Application responsibilities

- Message transport and bulletin-board persistence
- Network retries and delivery coordination
- Epoch timing, wall-clock deadlines, and scheduling
- Out-of-band digest comparison and split-view detection plumbing
- UI, storage, and deployment-specific operational policy
