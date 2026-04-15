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

## What your application should keep

- the frozen `rosterHash`
- the published `manifest` and `manifestHash`
- the derived `sessionId`
- the signed public payloads exactly as posted on the board
- the organizer’s final `countedParticipantIndices` from `ballot-close`

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
    optionList: ["Option A", "Option B", "Option C"],
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
- `prepareAggregateForDecryption(...)`
- `createDecryptionShare(...)`
- `createDecryptionSharePayload(...)`
- `createTallyPublicationPayload(...)`

In practice, most integrations split them by phase:

- phase `0`: `createManifestPublicationPayload(...)`, `createRegistrationPayload(...)`, `createManifestAcceptancePayload(...)`
- phases `1` to `4`: DKG commitments, encrypted shares, Feldman commitments, and key-derivation confirmations
- phase `5`: `createBallotSubmissionPayload(...)`
- phase `6`: `createBallotClosePayload(...)`
- phase `7`: `prepareAggregateForDecryption(...)`, `createDecryptionShare(...)`, `createDLEQProof(...)`, `createDecryptionSharePayload(...)`
- phase `8`: `combineDecryptionShares(...)`, `createTallyPublicationPayload(...)`

These builders sign and encode published payloads. Your application still owns participant key custody, local trustee state, bulletin-board posting, and the orchestration that decides when each phase is complete.

For the reveal path, phase `7` is not a single builder call. Each trustee first prepares the accepted aggregate for decryption, then computes the partial share against that prepared ciphertext, proves it against the trustee verification key, and only then signs the `decryption-share` payload.

```typescript
import {
    RISTRETTO_GROUP,
    SHIPPED_PROTOCOL_VERSION,
    createDLEQProof,
    createDecryptionShare,
    createDecryptionSharePayload,
    deriveTranscriptVerificationKey,
    prepareAggregateForDecryption,
} from "threshold-elgamal";

const preparedAggregate = prepareAggregateForDecryption({
    aggregate: optionAggregation.aggregate,
    publicKey: jointPublicKey,
    protocolVersion: SHIPPED_PROTOCOL_VERSION,
    manifestHash,
    sessionId,
    optionIndex: optionAggregation.optionIndex,
});

const decryptionShare = createDecryptionShare(
    preparedAggregate.ciphertext,
    share,
);

const proof = await createDLEQProof(
    share.value,
    {
        publicKey: deriveTranscriptVerificationKey(
            qualifiedDealerCommitments,
            participantIndex,
            RISTRETTO_GROUP,
        ),
        ciphertext: preparedAggregate.ciphertext,
        decryptionShare: decryptionShare.value,
    },
    RISTRETTO_GROUP,
    {
        protocolVersion: SHIPPED_PROTOCOL_VERSION,
        suiteId: RISTRETTO_GROUP.name,
        manifestHash,
        sessionId,
        label: "decryption-share-dleq",
        participantIndex,
        optionIndex: optionAggregation.optionIndex,
    },
);

const decryptionSharePayload = await createDecryptionSharePayload(
    authPrivateKey,
    {
        sessionId,
        manifestHash,
        participantIndex,
        optionIndex: optionAggregation.optionIndex,
        transcriptHash: optionAggregation.aggregate.transcriptHash,
        ballotCount: optionAggregation.aggregate.ballotCount,
        decryptionShare: decryptionShare.value,
        proof,
    },
);
```

`prepareAggregateForDecryption(...)` returns the original aggregate when `c1` is already non-identity. If an accepted aggregate lands on identity `c1`, it deterministically adds a public encryption of zero so the tally stays the same while the DLEQ statement remains meaningful.

## Ballot close

`ballot-close` is mandatory before decryption and tally verification.

Its rules are:

- it must be signed by the organizer, defined as the manifest publisher
- it contains sorted, unique participant indices
- every included participant must have a complete ballot
- the included set must contain at least `k` participants
- omitted but otherwise valid ballots are excluded in a publicly auditable way

This is an administrative cutoff, not a fairness proof about waiting long enough.

## Late ballots and excluded voters

The verifier keeps a public distinction between ballots that were posted and ballots that were counted.

```typescript
const ballotClosePayload = await createBallotClosePayload(organizerPrivateKey, {
    sessionId,
    manifestHash,
    participantIndex: 1,
    countedParticipantIndices: [1, 2, 3, 4],
});

const verified = await verifyElectionCeremony(bundle);

console.log(verified.countedParticipantIndices); // [1, 2, 3, 4]
console.log(verified.excludedParticipantIndices); // for example [5, 6]
```

Participants `5` and `6` may still have posted otherwise valid ballots. They stay visible on the board, but the verifier excludes them from aggregate recomputation because the organizer omitted them from the signed close payload.

## End-to-end verification

Use `verifyElectionCeremony(...)` to replay the public ceremony from manifest publication through tally publication in one pass. The verifier checks:

- the frozen manifest and session context
- registrations and manifest acceptances
- the DKG transcript and joint public key
- the counted ballot set selected by `ballot-close`
- locally recomputed per-option aggregates
- decryption shares
- tally publications
- board-consistency digests and audit metadata

For verifier-first integration code, start with [Verifying a public board](./verifying-a-public-board/). For exact payload JSON, use [Published payload examples](./published-payload-examples/). The repository integration tests exercise the same flow, but the harness is not part of the supported public API.
