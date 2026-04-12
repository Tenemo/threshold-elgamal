# threshold-elgamal

[![npm version](https://badge.fury.io/js/threshold-elgamal.svg)](https://www.npmjs.com/package/threshold-elgamal)
[![npm downloads](https://img.shields.io/npm/dm/threshold-elgamal)](https://www.npmjs.com/package/threshold-elgamal)

---

[![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/threshold-elgamal/ci.yml?branch=master&label=passing%20tests)](https://github.com/Tenemo/threshold-elgamal/actions/workflows/ci.yml)
[![Tests coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/threshold-elgamal/coverage-badge.json)](https://tenemo.github.io/threshold-elgamal/coverage-summary.json)
[![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/threshold-elgamal/pages.yml?branch=master&label=docs)](https://github.com/Tenemo/threshold-elgamal/actions/workflows/pages.yml)

---

[![Node version](https://img.shields.io/badge/node-%E2%89%A524.14.1-5FA04E?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/github/license/Tenemo/threshold-elgamal)](LICENSE)

`threshold-elgamal` is a browser-native TypeScript library for verifiable score-voting research prototypes. The shipped beta line is focused on one workflow only:

- additive ElGamal on `ristretto255`
- honest-majority GJKR DKG
- fixed score voting in `1..10`
- one public manifest shape: `rosterHash` and `optionList`
- organizer-signed `ballot-close` before decryption
- full local recomputation and full ceremony verification from the public board

This package is library-only. WebSockets, retries, persistence, bulletin-board storage, mobile lifecycle handling, reminders, and organizer UX live in the application.

This is a hardened research prototype. It has not been audited.

## Installation

```bash
npm install threshold-elgamal
```

## Runtime requirements

- Use ESM imports such as `import { createElectionManifest } from 'threshold-elgamal'`.
- Browsers need native `bigint` together with Web Crypto.
- Node requires version `24.14.1` or newer with `globalThis.crypto`.
- Authentication signatures require Web Crypto `Ed25519`.
- Transport share exchange requires Web Crypto `X25519`.

See [Runtime and compatibility](https://tenemo.github.io/threshold-elgamal/guides/runtime-and-compatibility/) for the tested browser and Node matrix.

## Start here

- [Verifying a public board](https://tenemo.github.io/threshold-elgamal/guides/verifying-a-public-board/): start here for `tryVerifyElectionCeremony(...)` and `verifyElectionCeremony(...)`.
- [Browser and worker usage](https://tenemo.github.io/threshold-elgamal/guides/browser-and-worker-usage/): start here for key generation, manifest setup, and encrypted transport envelopes.
- [Published payload examples](https://tenemo.github.io/threshold-elgamal/guides/published-payload-examples/): start here if you need concrete JSON, posting, or persistence patterns.
- [Honest-majority voting flow](https://tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow/): read this for the supported phase-by-phase transcript story.

## Documentation

- Hosted documentation site: [tenemo.github.io/threshold-elgamal](https://tenemo.github.io/threshold-elgamal/)
- Get started: [tenemo.github.io/threshold-elgamal/guides/getting-started](https://tenemo.github.io/threshold-elgamal/guides/getting-started/)
- Verifying a public board: [tenemo.github.io/threshold-elgamal/guides/verifying-a-public-board](https://tenemo.github.io/threshold-elgamal/guides/verifying-a-public-board/)
- Browser and worker usage: [tenemo.github.io/threshold-elgamal/guides/browser-and-worker-usage](https://tenemo.github.io/threshold-elgamal/guides/browser-and-worker-usage/)
- Published payload examples: [tenemo.github.io/threshold-elgamal/guides/published-payload-examples](https://tenemo.github.io/threshold-elgamal/guides/published-payload-examples/)
- Honest-majority voting flow: [tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow](https://tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow/)
- Runtime and compatibility: [tenemo.github.io/threshold-elgamal/guides/runtime-and-compatibility](https://tenemo.github.io/threshold-elgamal/guides/runtime-and-compatibility/)
- Security boundary: [tenemo.github.io/threshold-elgamal/guides/security-and-non-goals](https://tenemo.github.io/threshold-elgamal/guides/security-and-non-goals/)
- Production voting safety review: [tenemo.github.io/threshold-elgamal/guides/production-voting-safety-review](https://tenemo.github.io/threshold-elgamal/guides/production-voting-safety-review/)
- API docs: [tenemo.github.io/threshold-elgamal/api](https://tenemo.github.io/threshold-elgamal/api/)

## Browser support

The shipped cryptographic browser path is fixed:

- `Ed25519` for protocol payload signatures
- `X25519` for encrypted share transport

Practical browser baseline for the public workflow:

- Chrome and Edge `137+`
- Firefox `130+`
- Safari `18.4+`
- iOS and iPadOS browsers on the Safari `18.4+` WebKit generation

Older browsers, stale embedded webviews, and runtimes without Web Crypto `X25519` support are not supported.

## Supported workflow

The supported boardroom flow is:

1. Freeze the roster in the application and hash it with `hashRosterEntries(...)`.
2. Build the minimal manifest with `createElectionManifest({ rosterHash, optionList })`.
3. Publish the manifest, registrations, and manifest acceptances.
4. Run the honest-majority GJKR transcript.
5. Post ballot payloads for complete `1..10` score ballots.
6. Post one organizer-signed `ballot-close` payload that freezes which complete ballots are counted.
7. Post threshold decryption shares and tally publications for the close-selected ballot set.
8. Verify the whole ceremony with `verifyElectionCeremony(...)`.

The cryptographic threshold is derived internally from the accepted registration roster:

- `k = ceil(n / 2)`
- odd participant counts are recommended
- even participant counts are supported and use `k = n / 2`

There is no supported `n-of-n` mode and no supported public `k-of-n` configuration.

Transcript verification requires key-derivation confirmations from every qualified participant.

See [Honest-majority voting flow](https://tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow/) for the full phase-by-phase transcript.

## Getting started

```typescript
import {
    createElectionManifest,
    deriveSessionId,
    hashElectionManifest,
    hashRosterEntries,
    majorityThreshold,
} from "threshold-elgamal";

const rosterHash = await hashRosterEntries([
    {
        participantIndex: 1,
        authPublicKey: "auth-key-1",
        transportPublicKey: "transport-key-1",
    },
    {
        participantIndex: 2,
        authPublicKey: "auth-key-2",
        transportPublicKey: "transport-key-2",
    },
    {
        participantIndex: 3,
        authPublicKey: "auth-key-3",
        transportPublicKey: "transport-key-3",
    },
]);

const manifest = createElectionManifest({
    rosterHash,
    optionList: ["Option A", "Option B"],
});

const manifestHash = await hashElectionManifest(manifest);
const sessionId = await deriveSessionId(
    manifestHash,
    rosterHash,
    "public-nonce",
    "2026-04-11T12:00:00Z",
);

console.log(majorityThreshold(3)); // 2
console.log(sessionId.length); // 64
```

If your application consumes a complete public board, start with [Verifying a public board](https://tenemo.github.io/threshold-elgamal/guides/verifying-a-public-board/) and then move directly to the verifier entry point:

```typescript
import {
    tryVerifyElectionCeremony,
    type VerifyElectionCeremonyInput,
} from "threshold-elgamal";

const bundle: VerifyElectionCeremonyInput = {
    manifest,
    sessionId,
    dkgTranscript,
    ballotPayloads,
    ballotClosePayload,
    decryptionSharePayloads,
    tallyPublications,
};

const result = await tryVerifyElectionCeremony(bundle);

if (!result.ok) {
    console.error(result.error.stage, result.error.code, result.error.reason);
} else {
    console.log(result.verified.perOptionTallies);
    console.log(result.verified.boardAudit.overall.fingerprint);
}
```

The root package also exposes builders for the signed protocol payloads used across the shipped ceremony, including:

- manifest publication
- registration
- manifest acceptance
- phase checkpoints
- Pedersen commitments
- encrypted dual-share envelopes
- Feldman commitments
- key-derivation confirmations
- ballot submission
- ballot close
- decryption shares
- tally publication

For the reveal path, the public root surface is intentionally two-step:

- compute each partial share with `createDecryptionShare(...)`
- prove and publish it with `createDLEQProof(...)` and `createDecryptionSharePayload(...)`

After collecting a threshold subset, recover the tally with `combineDecryptionShares(...)`.

For concrete posted JSON shapes, use [Published payload examples](https://tenemo.github.io/threshold-elgamal/guides/published-payload-examples/).

## Security boundary

The library is designed for an honest-origin, honest-client, static-adversary setting.

What it tries to enforce:

- additive-only tallying on `ristretto255`
- fixed `1..10` score ballots
- grouped per-option ballot verification
- mandatory local aggregate recomputation before decryption
- organizer-visible and auditable ballot cutoff through `ballot-close`
- end-to-end ceremony verification from signed public payloads

What it does not claim:

- coercion resistance
- receipt-freeness
- cast-as-intended against a compromised client
- constant-time JavaScript `bigint` execution
- production readiness

`ballot-close` is an auditable administrative cutoff, not a fairness proof about board arrival order. The library proves what was counted, not whether the organizer waited long enough before closing.

For a production-threat-model verdict that maps these boundaries to the shipped verifier and tests, read the [production voting safety review](https://tenemo.github.io/threshold-elgamal/guides/production-voting-safety-review/).

## Development

```bash
pnpm install
pnpm run lint
pnpm run tsc
pnpm run test
pnpm run build
pnpm run verify:docs
pnpm run docs:build:site
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
