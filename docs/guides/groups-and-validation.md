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

## Common failures

- `InvalidGroupElementError` for invalid subgroup elements or public keys
- `InvalidGroupElementError` also covers shipped additive ciphertexts with
  invalid subgroup-or-identity components
- `InvalidScalarError` for invalid bounds, randomness, or out-of-range scalars
- `PlaintextDomainError` for plaintexts outside the accepted mode-specific domain

## Practical rule

Resolve the group once, keep it explicit everywhere, and validate any value that comes from outside your trust boundary before secret-dependent use.
