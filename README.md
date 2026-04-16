# threshold-elgamal

[![npm downloads](https://img.shields.io/npm/dm/threshold-elgamal?color=5FA04E)](https://www.npmjs.com/package/threshold-elgamal)

---

[![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/threshold-elgamal/ci.yml?branch=master&label=passing%20tests&color=5FA04E)](https://github.com/Tenemo/threshold-elgamal/actions/workflows/ci.yml)
[![Tests coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/threshold-elgamal/coverage-badge.json)](https://tenemo.github.io/threshold-elgamal/coverage-summary.json)
[![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/threshold-elgamal/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/threshold-elgamal/actions/workflows/pages.yml)

---

[![License](https://img.shields.io/github/license/Tenemo/threshold-elgamal)](LICENSE)

`threshold-elgamal` is a browser-native TypeScript library for verifiable score-voting research prototypes. It focuses on one workflow:

- additive ElGamal on `ristretto255`
- honest-majority GJKR DKG
- one explicit global contiguous score range per ceremony
- one public manifest shape: `rosterHash`, `optionList`, and `scoreRange`
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
- Node must satisfy the package `engines.node` requirement and expose `globalThis.crypto`.
- Authentication signatures require Web Crypto `Ed25519`.
- Transport share exchange requires Web Crypto `X25519`.

See [Runtime and compatibility](https://tenemo.github.io/threshold-elgamal/guides/runtime-and-compatibility/) for environment requirements.

## Documentation

- Homepage: [tenemo.github.io/threshold-elgamal](https://tenemo.github.io/threshold-elgamal/)
- Getting started: [tenemo.github.io/threshold-elgamal/guides/getting-started](https://tenemo.github.io/threshold-elgamal/guides/getting-started/)
- Runtime and compatibility: [tenemo.github.io/threshold-elgamal/guides/runtime-and-compatibility](https://tenemo.github.io/threshold-elgamal/guides/runtime-and-compatibility/)
- Browser and worker usage: [tenemo.github.io/threshold-elgamal/guides/browser-and-worker-usage](https://tenemo.github.io/threshold-elgamal/guides/browser-and-worker-usage/)
- Honest-majority voting flow: [tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow](https://tenemo.github.io/threshold-elgamal/guides/three-participant-voting-flow/)
- Published payload examples: [tenemo.github.io/threshold-elgamal/guides/published-payload-examples](https://tenemo.github.io/threshold-elgamal/guides/published-payload-examples/)

---

- Verifying a public board: [tenemo.github.io/threshold-elgamal/guides/verifying-a-public-board](https://tenemo.github.io/threshold-elgamal/guides/verifying-a-public-board/)
- Security boundary: [tenemo.github.io/threshold-elgamal/guides/security-and-non-goals](https://tenemo.github.io/threshold-elgamal/guides/security-and-non-goals/)
- Production voting safety review: [tenemo.github.io/threshold-elgamal/guides/production-voting-safety-review](https://tenemo.github.io/threshold-elgamal/guides/production-voting-safety-review/)

---

- API docs: [tenemo.github.io/threshold-elgamal/api](https://tenemo.github.io/threshold-elgamal/api/)

## Browser support

The cryptographic browser path is fixed:

- `Ed25519` for protocol payload signatures
- `X25519` for encrypted share transport

- Use modern browsers that expose Web Crypto `Ed25519`, Web Crypto `X25519`, and native `bigint`
- Validate your target environments with `pnpm exec tsx ./tools/ci/verify-browser-compat.ts` before deployment

Older browsers, stale embedded webviews, and runtimes without Web Crypto `X25519` support are not supported.

## Supported workflow

The supported boardroom flow is:

1. Freeze the roster in the application and hash it with `hashRosterEntries(...)`.
2. Build the manifest with `createElectionManifest({ rosterHash, optionList, scoreRange })`.
3. Publish the manifest, registrations, and manifest acceptances.
4. Run the honest-majority GJKR transcript.
5. Post ballot payloads for complete scores inside the manifest-declared range.
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
    scoreRange: { min: 1, max: 10 },
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

The root package exposes the builders and lower-level helpers required for the documented ceremony, including:

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

The reveal path also works from the root package:

- prepare the accepted aggregate with `prepareAggregateForDecryption(...)`
- compute each partial share with `createDecryptionShare(...)`
- prove it with `createDLEQProof(...)`
- publish it with `createDecryptionSharePayload(...)`

After collecting a threshold subset, recover the tally with `combineDecryptionShares(...)` against the prepared aggregate ciphertext.

The grouped public submodules remain available when you prefer narrower imports by subsystem, but the supported full ceremony does not require them.

For concrete posted JSON shapes, use [Published payload examples](https://tenemo.github.io/threshold-elgamal/guides/published-payload-examples/).

## Security boundary

The library is designed for an honest-origin, honest-client, static-adversary setting.

What it tries to enforce:

- additive-only tallying on `ristretto255`
- one explicit global contiguous manifest score range
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

`ballot-close` is an auditable administrative cutoff, not a fairness proof about board arrival order. The library proves which ballots count, not whether the organizer waited long enough before closing.

For a production-threat-model verdict that maps these boundaries to the verifier and tests, read the [production voting safety review](https://tenemo.github.io/threshold-elgamal/guides/production-voting-safety-review/).

## Development

```bash
pnpm install
pnpm run lint
pnpm run tsc
pnpm run test
pnpm run coverage:node
pnpm run build
pnpm exec playwright install chromium firefox webkit
pnpm exec tsx ./tools/ci/verify-browser-compat.ts
pnpm run verify:docs
pnpm run docs:build:site
pnpm run smoke:pack
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
