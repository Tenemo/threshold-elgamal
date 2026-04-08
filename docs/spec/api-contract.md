# API contract

The current package draws a hard boundary between the shipped cryptographic library and the surrounding application.

## Library responsibilities

- Group definitions and scalar arithmetic
- Safe additive ElGamal on the root package
- Ciphertext combination helpers for the shipped additive workflow
- Serialization and deterministic encoding helpers
- Runtime validation for public inputs, plaintext domains, and subgroup membership
- Dealer-based threshold sharing and additive threshold decryption
- Standalone VSS, proof, protocol, transport, and log-driven DKG helpers

## Application responsibilities

- Bulletin-board storage, deployment-specific transport plumbing, and operational policy
- Tally policy, additive bound selection, and result interpretation
- UI, orchestration, retries, and deadline handling
- Final application decisions about trustee workflows, deadlines, and complaint policy
