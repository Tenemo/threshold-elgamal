# Errors and failure modes

The library exposes dedicated error classes so callers can distinguish input mistakes from unsupported runtime conditions.

## Common error classes

- `InvalidScalarError`: invalid randomness, bounds, or modular arithmetic inputs
- `InvalidGroupElementError`: value is not a valid subgroup element or public key
- `PlaintextDomainError`: plaintext is outside the accepted range for the selected mode
- `UnsupportedSuiteError`: unknown group identifier or missing Web Crypto support
- `InvalidPayloadError`: malformed hex or challenge-encoding input

## How to handle them

- Treat `UnsupportedSuiteError` as an environment or configuration failure
- Treat `Invalid*` and `PlaintextDomainError` as caller or input validation failures
- Do not catch and ignore these errors silently; they indicate a violated invariant

## Additive-mode failures

- Additive mode rejects values outside `0..bound`
- Additive decryption fails if the ciphertext decodes outside the supplied search bound
