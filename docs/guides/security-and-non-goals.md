# Security and non-goals

These statements describe the current shipped surface only.

## What the library does guarantee

- built-in RFC 7919 groups with first-class `q`
- deterministic, validated `h` values
- subgroup validation before secret-dependent use
- cryptographically secure randomness with rejection sampling
- additive ElGamal as the safe public ElGamal mode
- explicit group selection with no silent default suite

## What the library does not claim

- no claim of constant-time `bigint` arithmetic in JavaScript
- no claim of production audit status
- no shipped threshold decryption yet
- no shipped zero-knowledge proofs yet
- no shipped DKG, transport, or signed payload APIs yet

## Practical defaults

- Prefer `ffdhe3072` unless you have a documented reason to pick a different built-in suite
- Prefer the safe additive surface for confidential tallies
- Treat additive mode as the only shipped ElGamal mode

## Future work boundary

The roadmap may mention threshold, proofs, transport, and DKG, but those are not part of the current public contract until they ship and appear in the exported API reference.
