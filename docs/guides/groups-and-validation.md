# Groups and validation

The current package ships three RFC 7919 FFDHE suites:

- `ffdhe2048`
- `ffdhe3072`
- `ffdhe4096`

All public APIs require one of these identifiers explicitly. There is no implicit default suite.

## Group objects

`getGroup()` returns a frozen object with:

- `p`: safe-prime modulus
- `q`: prime-order subgroup order
- `g`: primary generator
- `h`: deterministic secondary generator
- `bits`
- `byteLength`
- `securityEstimate`

## Validation helpers

Useful exported helpers include:

- `assertValidPublicKey` for subgroup public keys
- `assertValidAdditiveCiphertext` and `assertValidFreshAdditiveCiphertext`
- `assertScalarInZq`

## Current primitive surface

- Hashing uses SHA-256
- HKDF uses HKDF-SHA-256
- Encoded bigint values use fixed-width lowercase big-endian hexadecimal strings
- Challenge and transcript inputs use injective length-prefixed `encodeForChallenge()` encoding

## Common failures

- `InvalidGroupElementError` for invalid subgroup elements or public keys
- `InvalidGroupElementError` also covers shipped additive ciphertexts with
  invalid subgroup-or-identity components
- `InvalidScalarError` for invalid bounds, randomness, or out-of-range scalars
- `PlaintextDomainError` for plaintexts outside the accepted mode-specific domain
- `UnsupportedSuiteError` for unknown group identifiers or missing Web Crypto support
- `InvalidPayloadError` for malformed hex or challenge-encoding input

## Handling validation failures

- Treat `UnsupportedSuiteError` as an environment or configuration failure
- Treat `Invalid*` and `PlaintextDomainError` as caller or input validation failures
- Do not catch and ignore these errors silently; they indicate a violated invariant

## Additive-mode failures

- Additive mode rejects values outside `0..bound`
- Additive decryption fails if the ciphertext decodes outside the supplied search bound

## Practical rule

Resolve the group once, keep it explicit everywhere, and validate any value that comes from outside your trust boundary before secret-dependent use.
