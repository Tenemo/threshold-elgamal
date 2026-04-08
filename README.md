# Threshold ElGamal

[![npm version](https://badge.fury.io/js/threshold-elgamal.svg)](https://badge.fury.io/js/threshold-elgamal)
[![npm downloads](https://img.shields.io/npm/dm/threshold-elgamal)](https://www.npmjs.com/package/threshold-elgamal)

---

[![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/threshold-elgamal/ci.yml?branch=master&label=passing%20tests)](https://github.com/Tenemo/threshold-elgamal/actions/workflows/ci.yml)
[![Tests coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Tenemo/threshold-elgamal/master/docs/public/coverage-badge.json)](docs/public/coverage-summary.json)
[![Docs build](https://img.shields.io/github/actions/workflow/status/Tenemo/threshold-elgamal/pages.yml?branch=master&label=docs)](https://github.com/Tenemo/threshold-elgamal/actions/workflows/pages.yml)

---

[![Node version](https://img.shields.io/badge/node-%E2%89%A524.14.1-5FA04E?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/github/license/Tenemo/threshold-elgamal)](LICENSE)

---

`threshold-elgamal` is a TypeScript library for applications where a group of
people need to submit encrypted scores, verify a shared public record, and
reveal only the final result once enough participants cooperate.

In practice, that means browser-native finite-field ElGamal research
prototypes for verifiable voting, encrypted group decisions, and other
small-ceremony threshold workflows built on native `bigint`.

The published package has `0` runtime dependencies and ships as a fully
self-contained library.

This library is a hardened research prototype. It has not been audited.

Start with these guides:

- [Get started](https://tenemo.github.io/threshold-elgamal/guides/getting-started/)
- [Three-participant voting flow](https://tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow/)
- [Security and non-goals](https://tenemo.github.io/threshold-elgamal/guides/security-and-non-goals/)

## What the library includes

### Encryption and validation

- [Validated RFC 7919 FFDHE groups and subgroup checks](https://tenemo.github.io/threshold-elgamal/guides/groups-and-validation/) define the group model and the input rules the library enforces.
- [Additive ElGamal, ciphertext combination, and bounded discrete-log recovery](https://tenemo.github.io/threshold-elgamal/guides/additive-elgamal/) cover the safe encryption path used by the root package.
- [The safe root package API](https://tenemo.github.io/threshold-elgamal/api/root-package/) exposes the additive-only surface for encryption, decryption, encoding, and validation.

### Threshold and protocol building blocks

- [Threshold sharing and decryption helpers](https://tenemo.github.io/threshold-elgamal/api/reference/threshold/) provide dealer-based Shamir sharing, verified decryption shares, and aggregate decryption support.
- [Feldman and Pedersen VSS helpers](https://tenemo.github.io/threshold-elgamal/api/reference/vss/) cover verifiable secret sharing commitments and share checks.
- [Typed protocol payloads, manifest handling, transcript hashing, and published tally verification](https://tenemo.github.io/threshold-elgamal/api/reference/protocol/) cover the library's signed ceremony and tally surface.
- [Log-driven Joint-Feldman and GJKR reducers](https://tenemo.github.io/threshold-elgamal/api/reference/dkg/) provide the distributed key-generation state machines behind the threshold workflow.

### Proofs, transport, and runtime

- [Schnorr, DLEQ, and disjunctive proofs](https://tenemo.github.io/threshold-elgamal/api/reference/proofs/) support ballot and decryption verification.
- [Authenticated transport envelopes and complaint-resolution helpers](https://tenemo.github.io/threshold-elgamal/api/reference/transport/) cover the share-delivery layer used by the DKG flow.
- [Runtime and browser compatibility guidance](https://tenemo.github.io/threshold-elgamal/guides/runtime-and-compatibility/) documents the supported environments and feature expectations.
- [The subpath overview](https://tenemo.github.io/threshold-elgamal/api/subpath-overview/) shows how the public API is split between the safe root package and narrower advanced modules.

## Installation

```bash
pnpm add threshold-elgamal
```

## Runtime requirements

- Use ESM imports such as `import { encryptAdditive } from 'threshold-elgamal'`. The published package does not expose CommonJS `require()` entry points.
- Browsers need native `bigint` together with Web Crypto (`crypto.subtle` and `crypto.getRandomValues`).
- Node requires version `24.14.1` or newer with `globalThis.crypto`.

## Quickstart

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

- Hosted documentation site: [tenemo.github.io/threshold-elgamal](https://tenemo.github.io/threshold-elgamal/)
- Get started: [tenemo.github.io/threshold-elgamal/guides/getting-started](https://tenemo.github.io/threshold-elgamal/guides/getting-started/)
- Build a voting flow: [tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow](https://tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow/)
- Security model: [tenemo.github.io/threshold-elgamal/guides/security-and-non-goals](https://tenemo.github.io/threshold-elgamal/guides/security-and-non-goals/)
- API reference: [tenemo.github.io/threshold-elgamal/api](https://tenemo.github.io/threshold-elgamal/api/)
- Docs source: [`docs/src/content/docs/`](docs/src/content/docs/)

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

## DKG benchmark

For the DKG benchmark sweep, run:

```bash
pnpm run bench:dkg -- --group=ffdhe3072 --transport=X25519 3,11,21,31,41,51
```

Measurements were collected on this machine:

- Windows 10 Pro 22H2
- Intel Core i9-14900K
- DDR5-5000 RAM

Results:

- Group: `ffdhe3072`
- Transport: `X25519`
- Total elapsed time: `2 h 25 min 49.572 s`

| Participants (`n`) | Threshold (`k`) | Transcript messages | Full voting flow   | Transcript verification | Total              |
| ------------------ | --------------- | ------------------- | ------------------ | ----------------------- | ------------------ |
| 3                  | 2               | 22                  | 21.322 s           | 729.839 ms              | 22.052 s           |
| 11                 | 6               | 166                 | 2 min 6.564 s      | 8.222 s                 | 2 min 14.786 s     |
| 21                 | 11              | 526                 | 8 min 2.140 s      | 29.292 s                | 8 min 31.432 s     |
| 31                 | 16              | 1086                | 19 min 55.017 s    | 1 min 5.193 s           | 21 min 0.210 s     |
| 41                 | 21              | 1846                | 39 min 54.015 s    | 1 min 46.184 s          | 41 min 40.199 s    |
| 51                 | 26              | 2806                | 1 h 9 min 19.986 s | 2 min 40.902 s          | 1 h 12 min 0.888 s |

The sweep scales superlinearly in both transcript volume and runtime, with the
`n=51`, `k=26` case producing `2806` transcript messages and taking just over
`72` minutes for a full run plus verification on this hardware.

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
