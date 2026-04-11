---
title: Honest-majority voting flow
description: The supported root-only ceremony flow on the current beta line.
sidebar:
  order: 3
---

This guide describes the supported ceremony shape on the current beta line:

1. Freeze the roster in the application and hash it.
2. Publish the minimal manifest.
3. Collect registrations and manifest acceptances.
4. Complete the honest-majority GJKR transcript.
5. Publish complete score ballots.
6. Publish one organizer-signed `ballot-close`.
7. Publish decryption shares and tallies for the close-selected ballot set.
8. Verify the entire ceremony from the public board.

The public package is root-only. Import everything from `threshold-elgamal`.

## Minimal manifest

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
    optionList: ["Option A"],
});

const manifestHash = await hashElectionManifest(manifest);
const sessionId = await deriveSessionId(
    manifestHash,
    rosterHash,
    "nonce-three-participants",
    "2026-04-11T12:00:00Z",
);

console.log(majorityThreshold(3)); // 2
```

The manifest does not carry `participantCount`, `reconstructionThreshold`, publication floors, or deadline metadata. The verifier derives `n` from the accepted registration roster and derives `k` internally as `ceil(n / 2)`.

## Supported public builders

The root package exposes public builders for the standard ceremony payloads:

- `createManifestPublicationPayload(...)`
- `createRegistrationPayload(...)`
- `createManifestAcceptancePayload(...)`
- `createPedersenCommitmentPayload(...)`
- `createEncryptedDualSharePayload(...)`
- `createFeldmanCommitmentPayload(...)`
- `createKeyDerivationConfirmationPayload(...)`
- `createBallotSubmissionPayload(...)`
- `createBallotClosePayload(...)`
- `createDecryptionSharePayload(...)`
- `createTallyPublicationPayload(...)`

## Ballot close

`ballot-close` is mandatory before decryption and tally verification.

Its rules are:

- it must be signed by the organizer, defined as the manifest publisher
- it contains sorted, unique participant indices
- every included participant must have a complete ballot
- the included set must contain at least `k` participants
- omitted but otherwise valid ballots are excluded in a publicly auditable way

This is an administrative cutoff, not a fairness proof about waiting long enough.

## End-to-end verification

Use `verifyElectionCeremonyDetailed(...)` to replay the public ceremony from manifest publication through tally publication in one pass. The verifier checks:

- the frozen manifest and session context
- registrations and manifest acceptances
- the DKG transcript and derived joint key
- the counted ballot set selected by `ballot-close`
- locally recomputed per-option aggregates
- decryption shares
- tally publications
- board-consistency digests and audit metadata

For an executable example, inspect the root-only public node integration tests in this repository.
