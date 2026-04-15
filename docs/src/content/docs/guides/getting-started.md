---
title: Get started
description: The shortest safe path into the root package, public-board verifier, and browser-native workflow.
sidebar:
  order: 1
---

Use the root package. The public surface is centered on one protocol story: honest-majority GJKR, fixed `1..10` score ballots, `ballot-close`, and full ceremony verification.

## Start with these rules

- The public manifest shape is only `rosterHash` and `optionList`.
- The library derives the threshold from the accepted registration roster as `k = ceil(n / 2)`.
- Ballots are fixed to complete `1..10` score ballots.
- The organizer closes counting with one signed `ballot-close` payload.
- Each trustee prepares the accepted aggregate with `prepareAggregateForDecryption(...)` and then computes a partial reveal with `createDecryptionShare(...)` before signing `createDecryptionSharePayload(...)`.
- Tally verification must be done against the close-selected ballot set, not against a server-supplied aggregate.

## Choose the workflow you need

- If you are building browser clients or worker code that creates payloads, start with [Browser and worker usage](./browser-and-worker-usage/).
- If you want the full phase-by-phase ceremony story, read [Honest-majority voting flow](./three-participant-voting-flow/).
- If you need exact JSON wire shapes, start with [Published payload examples](./published-payload-examples/).
- If you already have a complete public board bundle, start with [Verifying a public board](./verifying-a-public-board/).

## Verification quickstart

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
    console.log(result.verified.qualifiedParticipantIndices);
    console.log(result.verified.countedParticipantIndices);
    console.log(result.verified.perOptionTallies);
    console.log(result.verified.boardAudit.overall.fingerprint);
}
```

Use `verifyElectionCeremony(...)` when you want the same checks but prefer exceptions over a structured result.

## What to persist in your application

- Keep `rosterHash`, `manifest`, `manifestHash`, and `sessionId` together. They define the public ceremony context.
- Persist the signed board payloads exactly as published. The verifier expects the original `{ payload, signature }` objects.
- If you store verifier output, convert `bigint` values such as tallies to strings first.

## Related pages

- For installation and the top-level package overview, read [README.md](https://github.com/Tenemo/threshold-elgamal#readme).
- For runtime prerequisites and platform assumptions, read [Runtime and compatibility](./runtime-and-compatibility/).
- For browser-native setup and worker patterns, read [Browser and worker usage](./browser-and-worker-usage/).
- For the supported ceremony path, read [Honest-majority voting flow](./three-participant-voting-flow/).
- For concrete JSON payload shapes, read [Published payload examples](./published-payload-examples/).
- For verifier usage and stable failure handling, read [Verifying a public board](./verifying-a-public-board/).
- For the security boundary, read [Security and non-goals](./security-and-non-goals/).
- For a production-threat-model verdict, read [Production voting safety review](./production-voting-safety-review/).
- The [API docs](../api/) list exact signatures and exported types.
