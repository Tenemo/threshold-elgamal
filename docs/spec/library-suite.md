# Mandatory suite

v2 defines one mandatory browser-native cryptographic suite.

## Group parameters

- RFC 7919 FFDHE groups: `ffdhe2048`, `ffdhe3072`, `ffdhe4096`
- Group objects expose `{ p, q, g, h, name, bits, securityEstimate }`
- `h` is derived deterministically from suite parameters and validated to lie in the prime-order subgroup

## Primitive selection

- Hash: SHA-256
- KDF: HKDF-SHA-256
- AEAD: AES-256-GCM
- Authentication signatures: ECDSA P-256
- Key agreement: X25519
- Fallback key agreement: P-256 ECDH when X25519 is unavailable

## Encoding

- Signed payloads use RFC 8785 canonical JSON
- BigInt values are encoded as fixed-width lowercase big-endian hexadecimal strings
- Width is tied to the selected group modulus size

## Mandatory version fields

Every protocol payload carries:

- `protocolVersion`
- `suiteId`
- `encodingVersion`
