# Threshold ElGamal

[![npm version](https://badge.fury.io/js/threshold-elgamal.svg)](https://badge.fury.io/js/threshold-elgamal)

`threshold-elgamal` is a browser-native TypeScript library for finite-field ElGamal research prototypes built on native `bigint`.

This library ships:

- validated RFC 7919 FFDHE groups with first-class `q`
- deterministic suite-derived `h`
- cryptographically secure randomness with rejection sampling
- additive ElGamal on the safe root package
- bounded discrete-log recovery and additive ciphertext combination helpers
- key generation helpers for the shipped additive workflow
- deterministic encoding helpers for serialization and challenge inputs
- dealer-based threshold sharing and decryption under the `./threshold` subpath
- Feldman and Pedersen VSS helpers under the `./vss` subpath
- Schnorr, DLEQ, and disjunctive proofs under the `./proofs` subpath
- canonical payload, transcript, manifest, and published-tally verification helpers under the `./protocol` subpath
- authenticated transport envelopes under the `./transport` subpath
- log-driven Joint-Feldman and GJKR reducers under the `./dkg` subpath

This library is a hardened research prototype. It is not audited production voting software.

## Release status

This repository tracks the `v2` line. Treat any published `0.1.x` package as
legacy and do not use it for new deployments.

Confirm that you are actually installing a `2.x` package before relying on the
typed protocol payloads, transcript-native complaint handling, or the published
tally verification helpers described in this repository.

## Installation

```bash
pnpm add threshold-elgamal
```

## Runtime requirements

- Use ESM imports such as `import { encryptAdditive } from 'threshold-elgamal'`. The published package does not expose CommonJS `require()` entry points.
- Browsers need native `bigint` together with Web Crypto (`crypto.subtle` and `crypto.getRandomValues`).
- Node requires version `24.14.1` or newer with `globalThis.crypto`.

## Safe quickstart

```typescript
import {
    addEncryptedValues,
    decryptAdditive,
    encryptAdditive,
    generateParameters,
    getGroup,
} from "threshold-elgamal";

const group = "ffdhe3072" as const;
const { publicKey, privateKey } = generateParameters(group);
const suite = getGroup(group);
const messageBound = 10n;
const tallyBound = 20n;

const left = encryptAdditive(6n, publicKey, group, messageBound);
const right = encryptAdditive(7n, publicKey, group, messageBound);
const sum = addEncryptedValues(left, right, group);

console.log(decryptAdditive(sum, privateKey, group, tallyBound)); // 13n
console.log(suite.q > 0n); // true
```

All public APIs require explicit group selection. There is no implicit default suite.

## Choosing an additive bound

- The encryption-time `bound` validates the plaintext for that one ciphertext. Use the maximum single message you allow.
- The decryption-time `bound` must cover the plaintext you expect to recover. For aggregates, that usually means the maximum tally, which is often larger than the per-message bound.
- Ciphertexts do not store or authenticate the bound for you. You must carry that policy in your application logic.
- Larger bounds make decryption slower and more memory-hungry because baby-step giant-step work grows roughly with `sqrt(bound)`.

For example, if each ballot is in `0..10` and you tally `50` ballots, encrypt each ballot with `10n` and decrypt the final sum with `500n`.

## Documentation

- Start at the docs portal: [docs/index.md](docs/index.md)
- Safe onboarding: [docs/guides/getting-started.md](docs/guides/getting-started.md)
- Additive mode guide: [docs/guides/additive-elgamal.md](docs/guides/additive-elgamal.md)
- Full 3-participant example: [docs/guides/three-participant-voting-flow.md](docs/guides/three-participant-voting-flow.md)
- Threshold and proof APIs: generated subpath docs under `docs/api/threshold`, `docs/api/vss`, and `docs/api/proofs`
- API reference: [docs/api/index.md](docs/api/index.md)
- Spec pages: [docs/spec/index.md](docs/spec/index.md)

## Changes since v0.x.x

This library has been substantially rewritten around a smaller and stricter public surface. The current release keeps the validated group definitions, deterministic suite-derived `h`, secure randomness, additive ElGamal, key generation, threshold sharing, proofs, protocol helpers, transport primitives, and log-driven DKG reducers. Raw multiplicative mode has been removed.

The reason is privacy leakage at the individual ciphertext level, not any problem with the geometric mean itself. In multiplicative ElGamal, `c2 = m * y^r mod p`. The masking term `y^r` is always a quadratic residue because it stays inside the prime-order subgroup, so `c2` inherits the Legendre symbol of `m`. Anyone observing the public ciphertext can compute that symbol and learn whether the plaintext score is in the quadratic-residue half of the score domain or the non-residue half. For a small domain such as `{1, ..., 10}`, that leaks about one bit per ballot and narrows each encrypted score from ten possibilities to roughly five before any decryption happens.

In additive ElGamal, `c2 = g^m * y^r mod p`. Both factors lie in the same prime-order subgroup, so `c2` is always a quadratic residue. The Legendre symbol therefore leaks nothing about the individual plaintext. That makes additive mode strictly better on per-ballot privacy.

The remaining inference problem comes from publishing exact aggregates over small groups, and that problem exists in both designs. If a small board publishes an exact sum, participants can reason backward from the total and their own vote. If it publishes an exact product, they can do the same thing from the product. No homomorphic encryption scheme fixes that by itself. The only real mitigations are changing what gets published, suppressing small results, or adding noise, all of which change the voting system semantics.

This does create a real tradeoff: additive homomorphism gives sums and arithmetic means, while multiplicative homomorphism gives products and geometric means. If a scoring system truly requires geometric-mean behavior, additive mode does not reproduce that semantics directly. The library now chooses the mode that does not leak information from each posted ciphertext.

## Development

```bash
pnpm install
pnpm run ci
```

For the DKG benchmark sweep, run:

```bash
pnpm run bench:dkg -- --group=ffdhe3072 --transport=X25519 3,11,21,31,41,51
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
