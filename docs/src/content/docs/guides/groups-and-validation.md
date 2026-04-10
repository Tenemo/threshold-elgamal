---
title: Groups and validation
description: Group selection, encoding rules, and the main validation failures callers should expect.
sidebar:
  order: 4
---

The current package ships one built-in tally suite:

- `ristretto255`

The suite is implicit in the public API. There is no public suite-selection switch.

## Fixed suite assumptions

- `deriveH()` returns the deterministic secondary generator encoding used by the shipped Pedersen commitments.
- Public additive, threshold, protocol, transport, and DKG helpers all assume `ristretto255`.
- Public point and scalar values use fixed-width lowercase hexadecimal encodings over canonical 32-byte values.

## Validation helpers

Useful exported helpers include:

- `assertValidPublicKey` for non-identity public keys
- `assertValidAdditiveCiphertext` and `assertValidFreshAdditiveCiphertext`
- `assertScalarInZq`

## Current primitive surface

- Manifest and transcript digests use SHA-256
- Transport key derivation uses HKDF-SHA-256
- The Ristretto255 backend and point derivation use `@noble/curves` and `@noble/hashes`
- Challenge and transcript inputs use canonical byte encodings with injective length-prefixed sequence handling

## Common failures

- `InvalidGroupElementError` for invalid Ristretto point encodings or public keys
- `InvalidGroupElementError` also covers additive ciphertexts with invalid point-or-identity components
- `InvalidScalarError` for invalid bounds, randomness, or out-of-range scalars
- `PlaintextDomainError` for plaintexts outside the accepted mode-specific domain
- `UnsupportedSuiteError` for missing Web Crypto support or unsupported runtime capabilities
- `InvalidPayloadError` for malformed hex or challenge-encoding input

## Handling validation failures

- Treat `UnsupportedSuiteError` as an environment or configuration failure
- Treat `Invalid*` and `PlaintextDomainError` as caller or input validation failures
- Do not catch and ignore these errors silently; they indicate a violated invariant

## Additive-mode failures

- Additive mode rejects values outside `0..bound`
- Additive decryption fails if the ciphertext decodes outside the supplied search bound
- The shipped voting layer adds a stricter rule on top: accepted ballot scores are fixed to `1..10`

## Practical rule

Treat the shipped suite as fixed, and validate any value that comes from outside your trust boundary before secret-dependent use.
