# Threshold ElGamal

[![npm version](https://badge.fury.io/js/threshold-elgamal.svg)](https://badge.fury.io/js/threshold-elgamal)

`threshold-elgamal` is a browser-native TypeScript library for finite-field ElGamal research prototypes built on native `bigint`.

The v2 rewrite currently ships:

- validated RFC 7919 FFDHE groups with first-class `q`
- deterministic suite-derived `h`
- CSPRNG-based key generation with rejection sampling
- multiplicative ElGamal
- additive ElGamal with bounded discrete-log recovery
- homomorphic ciphertext helpers
- foundational encoding helpers for later proof and protocol work

Threshold decryption, proofs, transport, and DKG are still under active rewrite and are not part of the current public API.

This library is a hardened research prototype. It is not audited production voting software.

## Current status

The old legacy threshold API has been removed from the main package surface.

The next rewrite batch is the dealer-based `k`-of-`n` threshold core. Until that lands, the public package exposes only the v2 core, serialization, and plain ElGamal modules.

## Installation

```bash
pnpm add threshold-elgamal
```

## Example

### Multiplicative ElGamal

```typescript
import {
    decrypt,
    encrypt,
    generateParameters,
    getGroup,
    multiplyEncryptedValues,
} from 'threshold-elgamal';

const group = 'ffdhe3072' as const;
const suite = getGroup(group);
const { publicKey, privateKey } = generateParameters(group);

const left = encrypt(6n, publicKey, group);
const right = encrypt(7n, publicKey, group);
const product = multiplyEncryptedValues(left, right, group);

console.log(decrypt(product, privateKey, group)); // 42n
console.log(suite.securityEstimate); // 125
```

### Additive ElGamal

```typescript
import {
    addEncryptedValues,
    decryptAdditive,
    encryptAdditive,
    generateParameters,
    getGroup,
} from 'threshold-elgamal';

const group = 'ffdhe3072' as const;
const suite = getGroup(group);
const { publicKey, privateKey } = generateParameters(group);

const left = encryptAdditive(6n, publicKey, group, 20n);
const right = encryptAdditive(7n, publicKey, group, 20n);
const sum = addEncryptedValues(left, right, group);

console.log(decryptAdditive(sum, privateKey, group, 20n)); // 13n
console.log(suite.q > 0n); // true
```

## Security notes

- All public APIs use `bigint`, never JavaScript `number`.
- Multiplicative mode accepts plaintexts in the range `1..p-1`.
- Additive mode accepts plaintexts in the range `0..bound`, where `bound < q`.
- Additive encryption requires an explicit caller-supplied bound so bounded discrete-log recovery stays operationally predictable.
- For score voting, use additive mode for confidential tallies. Raw multiplicative mode remains a lower-level primitive and exact products wrap once they exceed `p`.
- Raw multiplicative ElGamal with direct plaintext embedding leaks the plaintext's quadratic residuosity unless the plaintext is subgroup-encoded.
- Browser JavaScript `bigint` arithmetic is not constant-time. Do not overstate side-channel resistance on end-user devices.

For the frozen v2 invariants and suite notes, see [docs/spec/index.md](docs/spec/index.md).

## Development

```bash
pnpm install
pnpm run ci
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
