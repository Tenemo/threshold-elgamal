# API contract

The current package draws a hard boundary between the shipped cryptographic library and the surrounding application.

## Library responsibilities

- Group definitions and scalar arithmetic
- Safe additive ElGamal on the root package
- Ciphertext combination helpers for the shipped additive workflow
- Serialization and deterministic encoding helpers
- Runtime validation for public inputs, plaintext domains, and subgroup membership

## Application responsibilities

- Message transport, storage, and deployment-specific operational policy
- Tally policy, additive bound selection, and result interpretation
- UI, orchestration, retries, and deadline handling
- Threshold protocols, DKG, and proof systems until they are implemented and exported
