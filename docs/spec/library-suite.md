# Current suite

v2 fixes the current browser-native cryptographic suite for the shipped public API.

## Group parameters

- RFC 7919 FFDHE groups: `ffdhe2048`, `ffdhe3072`, `ffdhe4096`
- Group objects expose `{ p, q, g, h, name, bits, securityEstimate }`
- `h` is derived deterministically from suite parameters and validated to lie in the prime-order subgroup
- Built-in group objects are frozen at runtime

## Primitive selection

- Hash: SHA-256
- KDF: HKDF-SHA-256
- Randomness: Web Crypto `getRandomValues()` with rejection sampling

## Encoding

- Public APIs use native `bigint`
- Encoded bigint values use fixed-width lowercase big-endian hexadecimal strings
- Width is tied to the selected group modulus size
