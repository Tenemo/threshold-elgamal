# Threshold ElGamal

[![npm version](https://badge.fury.io/js/threshold-elgamal.svg)](https://www.npmjs.com/package/threshold-elgamal)
[![npm downloads](https://img.shields.io/npm/dm/threshold-elgamal)](https://www.npmjs.com/package/threshold-elgamal)

---

[![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/threshold-elgamal/ci.yml?branch=master&label=passing%20tests)](https://github.com/Tenemo/threshold-elgamal/actions/workflows/ci.yml)
[![Tests coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Tenemo/threshold-elgamal/master/docs/public/coverage-badge.json)](docs/public/coverage-summary.json)
[![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/threshold-elgamal/pages.yml?branch=master&label=docs)](https://github.com/Tenemo/threshold-elgamal/actions/workflows/pages.yml)

---

[![Node version](https://img.shields.io/badge/node-%E2%89%A524.14.1-5FA04E?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/github/license/Tenemo/threshold-elgamal)](LICENSE)

---

`threshold-elgamal` is a browser-native TypeScript library for verifiable score-voting research prototypes. The shipped `1.0.0-beta` line centers on additive ElGamal over `ristretto255`, threshold decryption, typed protocol payloads, authenticated share transport, and log-driven GJKR DKG.

The library is intentionally library-only. It stays pure, deterministic, synchronous, and Worker-safe. WebSockets, retries, persistence, bulletin-board storage, and application orchestration remain outside the package.

The cryptographic backend uses [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) where appropriate, plus Web Crypto for randomness, signatures, key agreement, and AES-GCM envelopes.

This library is a hardened research prototype. It has not been audited.

The current beta line supports:

- additive-only tallying
- fixed score voting in `1..10`
- per-option ballot slots with grouped voter-ballot verification
- strict-majority threshold policies `floor(n / 2) + 1 <= k <= n - 1`
- manifest acceptance, checkpoints, complaint handling, and `QUAL` reduction
- mandatory local aggregate recomputation before decryption and tally acceptance
- full board-audit and end-to-end ceremony verification helpers

Start with these guides:

- [Get started](https://tenemo.github.io/threshold-elgamal/guides/getting-started/)
- [Three-participant voting flow](https://tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow/)
- [Security and non-goals](https://tenemo.github.io/threshold-elgamal/guides/security-and-non-goals/)

## What the library includes

- [Ristretto255 assumptions, encodings, and validation rules](https://tenemo.github.io/threshold-elgamal/guides/groups-and-validation/) explain the fixed shipped suite and the input rules the library enforces.
- [Additive ElGamal, ciphertext combination, and bounded discrete-log recovery](https://tenemo.github.io/threshold-elgamal/guides/additive-elgamal/) cover the safe encryption path.
- [The root package API](https://tenemo.github.io/threshold-elgamal/api/root-package/) describes the supported public import surface.
- [The generated API reference](https://tenemo.github.io/threshold-elgamal/api/reference/threshold-elgamal/) contains the exact root-level types and signatures for additive, threshold, protocol, transport, runtime, serialization, and GJKR helpers.
- [Runtime and browser compatibility guidance](https://tenemo.github.io/threshold-elgamal/guides/runtime-and-compatibility/) documents the supported environments and feature expectations.

## Installation

```bash
pnpm add threshold-elgamal
```

## Runtime requirements

- Use ESM imports such as `import { encryptAdditive } from 'threshold-elgamal'`. The published package does not expose CommonJS `require()` entry points.
- Browsers need native `bigint` together with Web Crypto (`crypto.subtle` and `crypto.getRandomValues`).
- Node requires version `24.14.1` or newer with `globalThis.crypto`.

## Performance model

- Keep worker orchestration in the application. `threshold-elgamal` stays pure and importable inside a Web Worker, while the app decides pool size, chunking, and lifecycle.
- The library exposes a pluggable bigint backend through `setBigintMathBackend()` on the root package. JavaScript remains the default backend. Optional WASM acceleration should be installed explicitly by the caller.
- `minimumPublishedVoterCount` is a publication privacy floor for tally release. It is not the DKG reconstruction threshold.
- The current recommended default DKG regression size is `10` all-equal participants. Larger symmetric ceremonies remain experimental.

## Quickstart

```typescript
import {
    addEncryptedValues,
    decryptAdditive,
    deriveH,
    encryptAdditive,
    generateParameters,
} from "threshold-elgamal";

const { publicKey, privateKey } = generateParameters();
const messageBound = 10n;
const tallyBound = 20n;

const left = encryptAdditive(6n, publicKey, messageBound);
const right = encryptAdditive(7n, publicKey, messageBound);
const sum = addEncryptedValues(left, right);

console.log(decryptAdditive(sum, privateKey, tallyBound)); // 13n
console.log(deriveH().length); // 64 hex chars
```

The shipped canonical suite is implicit and fixed to `ristretto255`.

## Choosing additive bounds

- The encryption-time `bound` validates the plaintext for that one ciphertext. Use the maximum single message you allow.
- The decryption-time `bound` must cover the plaintext you expect to recover. For aggregates, that usually means the maximum tally, which is often larger than the per-message bound.
- Ciphertexts do not store or authenticate the bound for you. You must carry that policy in your application logic.
- Larger bounds make decryption slower and more memory-hungry because baby-step giant-step work grows roughly with `sqrt(bound)`.

For the shipped voting path, each score is in `1..10`. If you tally `50` ballots, encrypt each ballot with `10n` and decrypt the final sum with `500n`.

## Protocol defaults

- `reconstructionThreshold` is the real cryptographic threshold `k`.
- `minimumPublishedVoterCount` is the publication floor counted over distinct accepted voters.
- `ballotCompletenessPolicy` is fixed to `ALL_OPTIONS_REQUIRED`.
- `ballotFinality` is fixed to `first-valid`.
- `scoreDomain` is fixed to `1..10`.
- Accepted voters must submit exactly one ballot per option slot.
- `protocolVersion` is application-supplied manifest data and is transcript-bound by the verifier and proof contexts.

For end-to-end verification, the root package exposes `verifyElectionCeremonyDetailed(...)`. It verifies the manifest, registrations, acceptances, DKG transcript, local joint-key derivation, ballot proofs, locally recomputed per-option aggregates, decryption shares, tally publications, and board-consistency digests in one pass.

## Documentation

- Hosted documentation site: [tenemo.github.io/threshold-elgamal](https://tenemo.github.io/threshold-elgamal/)
- Get started: [tenemo.github.io/threshold-elgamal/guides/getting-started](https://tenemo.github.io/threshold-elgamal/guides/getting-started/)
- Build a voting flow: [tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow](https://tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow/)
- Security model: [tenemo.github.io/threshold-elgamal/guides/security-and-non-goals](https://tenemo.github.io/threshold-elgamal/guides/security-and-non-goals/)
- API reference: [tenemo.github.io/threshold-elgamal/api](https://tenemo.github.io/threshold-elgamal/api/)
- Docs source: [`docs/src/content/docs/`](docs/src/content/docs/)

## Beta-line notes

The current beta line intentionally standardizes the shipped workflow on Ristretto255, additive-only tallying, fixed `1..10` score voting semantics, and the renamed manifest fields `reconstructionThreshold` and `minimumPublishedVoterCount`.

That means the current beta API and wire format should be treated as a reset relative to earlier finite-field beta fixtures and examples. Regenerate vectors and re-sign manifests when moving old experiments onto this line.

## Development

```bash
pnpm install
pnpm run ci
```

## DKG benchmark

For the recommended default regression benchmark, run:

```bash
pnpm run bench:dkg -- --group=ristretto255 --transport=X25519 --options=3 10
```

Benchmark results depend heavily on device class and browser/runtime overhead. Treat the current all-to-all DKG path as a readiness spot check for `10` participants, not as evidence that the symmetric all-equal flow is suitable for large ceremonies.

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
