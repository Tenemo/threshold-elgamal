---
title: Verifying a public board
description: How to verify the published ceremony bundle, handle stable failures, and inspect counted and excluded voters.
sidebar:
  order: 2
---

Use this guide when your application already has the published ceremony bundle and needs a verifier entry point. This is the shortest safe path for bulletin-board readers, auditors, observers, and result-checking backends.

## What the verifier expects

The full verifier consumes one `VerifyElectionCeremonyInput` bundle:

- `manifest`
- `sessionId`
- `dkgTranscript`
- `ballotPayloads`
- `ballotClosePayloads`
- `decryptionSharePayloads`
- `tallyPublications` if you want published tally records checked against the recomputed tallies

`ballotClosePayloads` must contain the full published `ballot-close` board slot, not a prefiltered close record. The verifier audits that slot, collapses only exact retransmissions, and requires exactly one accepted close payload after audit.

If `tallyPublications` is omitted or empty, the verifier still replays the DKG, ballot, and decryption-share flow and still recomputes per-option tallies locally.

## Use the non-throwing verifier first

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
    ballotClosePayloads,
    decryptionSharePayloads,
    tallyPublications,
};

const result = await tryVerifyElectionCeremony(bundle);

if (!result.ok) {
    console.error(result.error.stage, result.error.code, result.error.reason);
    return;
}

console.log(result.verified.qualifiedParticipantIndices);
console.log(result.verified.countedParticipantIndices);
console.log(result.verified.excludedParticipantIndices);
console.log(result.verified.perOptionTallies);
console.log(result.verified.boardAudit.overall.fingerprint);
```

This is usually the best application entry point because it gives you a stable `stage`, `code`, and `reason` without exception handling.

## What the DKG verifier assumes

`verifyElectionCeremony(...)` delegates DKG validation to `verifyDKGTranscript(...)`, which currently consumes:

- the public signed DKG transcript
- `key-derivation-confirmation` payloads from every qualified participant

This verifier does not implement a public post-Feldman complaint/reconstruction phase. That means the current DKG check is participant-confirmed transcript verification, not the stronger fully public-data-only variant sometimes described in the GJKR literature. Lowering confirmation acceptance to threshold-many is out of scope unless that missing public consistency machinery is added.

## Use the throwing verifier when failure should abort immediately

```typescript
import { verifyElectionCeremony } from "threshold-elgamal";

const verified = await verifyElectionCeremony(bundle);

console.log(verified.manifestHash);
console.log(verified.boardAudit.overall.ceremonyDigest);
console.log(verified.perOptionAcceptedCounts);
```

This is convenient in tests, CLIs, and internal scripts where a thrown failure should stop the flow immediately.

## Stable failure categories

`tryVerifyElectionCeremony(...)` reports one of these verification stages:

- `manifest`
- `board`
- `dkg`
- `signatures`
- `ballots`
- `decryption`
- `tally`

The matching error codes are:

- `MANIFEST_INVALID`
- `BOARD_INVALID`
- `DKG_INVALID`
- `SIGNATURE_INVALID`
- `BALLOT_INVALID`
- `DECRYPTION_INVALID`
- `TALLY_INVALID`

Use the stage for coarse routing and the reason string for operator-facing detail.

## Ballot close and excluded voters

The verifier distinguishes between ballots that were posted and ballots that were counted.

```typescript
const verified = await verifyElectionCeremony(bundle);

console.log(verified.countedParticipantIndices); // for example [1, 2, 3, 4]
console.log(verified.excludedParticipantIndices); // for example [5, 6]
```

That means participants `5` and `6` can still appear on the board as published ballots while remaining excluded from the signed close-selected tally set.

## Persisting verification output

Published payloads are already JSON-safe, but verifier output contains `bigint` tallies. Convert them before storing or transmitting the verified result:

```typescript
const verifiedJson = JSON.stringify(
    result.ok ? result.verified : result.error,
    (_key, value) => (typeof value === "bigint" ? value.toString() : value),
);
```

For the published payload wire format itself, use [Published payload examples](./published-payload-examples/).
