---
title: Three-participant voting flow
description: The supported 3-participant workflow on the root-only beta line.
sidebar:
  order: 3
---

This guide describes the supported 3-participant flow on the current beta line:

- freeze the roster and manifest
- run a GJKR setup transcript
- publish additive ballots over the fixed score domain `1..10`
- recompute aggregates locally
- verify decryption shares and tallies

The public package is now root-only. Import everything from `threshold-elgamal`.

## Core setup values

```typescript
import {
    deriveSessionId,
    hashElectionManifest,
    hashRosterEntries,
    type ElectionManifest,
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

const manifest: ElectionManifest = {
    protocolVersion: "v1",
    reconstructionThreshold: 2,
    participantCount: 3,
    minimumPublishedVoterCount: 3,
    ballotCompletenessPolicy: "ALL_OPTIONS_REQUIRED",
    ballotFinality: "first-valid",
    scoreDomain: "1..10",
    rosterHash,
    optionList: ["Option A"],
    epochDeadlines: ["2026-04-08T12:00:00Z"],
};

const manifestHash = await hashElectionManifest(manifest);
const sessionId = await deriveSessionId(
    manifestHash,
    rosterHash,
    "nonce-three-participants",
    "2026-04-08T12:00:00Z",
);
```

The manifest no longer carries `suiteId`. The shipped suite is implicit and fixed to `ristretto255`.

For three participants, both `2 of 3` and `3 of 3` are supported. Choosing `3 of 3` removes dropout tolerance entirely, so any unresolved complaint, missing checkpoint signer, or missing decryption share prevents completion.

## Supported public workflow

1. Freeze the participant roster and publish the manifest.
2. Collect signed setup payloads for registrations, manifest acceptances, commitments, encrypted shares, complaints, resolutions, optional checkpoints, and key-derivation confirmations.
3. Accept ballots only after verifying signatures and score proofs against the manifest and session context.
4. Recompute every published aggregate locally from the accepted ballots.
5. Verify decryption shares and tally publications against the recomputed aggregates.
6. Accept the result only if the DKG transcript, ballots, decryption shares, tallies, and board consistency all verify together.

## Public helpers to reach for

- `createGjkrState()`, `processGjkrPayload()`, and `replayGjkrTranscript()` for deterministic reducer replay
- `verifyDKGTranscript()` for verifier-side DKG transcript validation
- `verifyAndAggregateBallots()` for local ballot verification and aggregation
- `verifyPublishedVotingResults()` for published tally verification
- `verifyElectionCeremonyDetailed()` for end-to-end ceremony verification

## What changed on this beta line

- There are no supported public subpath imports.
- There is no public group-selection step.
- The only supported DKG ceremony is GJKR.
- The manifest contract no longer carries `suiteId`.

For an end-to-end executable example, inspect the local development harness and node integration tests in this repository. For exact public signatures, use the generated [API reference](../api/reference/threshold-elgamal/).
