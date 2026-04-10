---
title: Three-participant voting flow
description: A complete signed and verified 3-participant voting flow from setup through tally publication.
sidebar:
  order: 3
---

This guide shows the shipped 3-participant flow on the current beta line:

- roster freeze, manifest hashing, and signed setup payloads
- GJKR-style setup material with Pedersen commitments, encrypted shares, and Feldman extraction proofs
- additive ballots with disjunctive proofs over the fixed score domain `1..10`
- local aggregate recomputation
- threshold decryption shares with DLEQ proofs
- typed ballot, decryption-share, tally, and board-audit helpers on the safe protocol path

The complete tested flow lives in `dev-support/voting-flow-harness.ts` and the node integration tests that exercise it.

## Imports and helper style

```typescript
import { getGroup, sha256, utf8ToBytes } from "threshold-elgamal/core";
import { addEncryptedValues, encryptAdditiveWithRandomness } from "threshold-elgamal/elgamal";
import {
    createDLEQProof,
    createDisjunctiveProof,
    createSchnorrProof,
    verifyDLEQProof,
    verifyDisjunctiveProof,
    verifySchnorrProof,
    type DLEQStatement,
    type ProofContext,
} from "threshold-elgamal/proofs";
import {
    deriveSessionId,
    hashElectionManifest,
    hashRosterEntries,
    scoreVotingDomain,
    verifyElectionCeremonyDetailed,
    type ElectionManifest,
} from "threshold-elgamal/protocol";
import {
    combineDecryptionShares,
    createVerifiedDecryptionShare,
    type Share,
} from "threshold-elgamal/threshold";
import {
    encryptEnvelope,
    generateAuthKeyPair,
    generateTransportKeyPair,
} from "threshold-elgamal/transport";
import {
    derivePedersenShares,
    generateFeldmanCommitments,
    generatePedersenCommitments,
} from "threshold-elgamal/vss";
```

## Freeze the roster and manifest

The library ships `hashRosterEntries()`, so the application can freeze the setup roster before building the manifest and signing the phase-0 payloads.

```typescript
const group = getGroup("ristretto255");

const participants = await Promise.all(
    [1, 2, 3].map(async (participantIndex) => ({
        participantIndex,
        auth: await generateAuthKeyPair(),
        transport: await generateTransportKeyPair("X25519"),
    })),
);

const rosterHash = await hashRosterEntries(
    participants.map((participant) => ({
        participantIndex: participant.participantIndex,
        authPublicKey: "exported-auth-key",
        transportPublicKey: "exported-transport-key",
    })),
);

const manifest: ElectionManifest = {
    protocolVersion: "v1",
    suiteId: group.name,
    reconstructionThreshold: 2,
    participantCount: 3,
    minimumPublishedVoterCount: 3,
    ballotFinality: "first-valid",
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

In this manifest, `reconstructionThreshold` is the real cryptographic threshold. `minimumPublishedVoterCount` is only the publication floor counted over distinct accepted voters.

## Build the setup transcript

For a 2-of-3 example, each participant uses a degree-1 secret polynomial and a matching degree-1 blinding polynomial. Feldman and Pedersen commitments are point encodings, and share delivery stays on the existing authenticated transport split.

```typescript
const dealerInputs = [
    { participantIndex: 1, secretPolynomial: [5n, 2n], blindingPolynomial: [11n, 7n] },
    { participantIndex: 2, secretPolynomial: [13n, 3n], blindingPolynomial: [17n, 5n] },
    { participantIndex: 3, secretPolynomial: [19n, 4n], blindingPolynomial: [23n, 6n] },
] as const;

for (const dealer of dealerInputs) {
    const pedersenCommitments = generatePedersenCommitments(
        dealer.secretPolynomial,
        dealer.blindingPolynomial,
        group,
    );
    const feldmanCommitments = generateFeldmanCommitments(
        dealer.secretPolynomial,
        group,
    );
    const shares = derivePedersenShares(
        dealer.secretPolynomial,
        dealer.blindingPolynomial,
        3,
        group.q,
    );

    for (const [offset, coefficient] of dealer.secretPolynomial.entries()) {
        const proofContext: ProofContext = {
            protocolVersion: "v1",
            suiteId: group.name,
            manifestHash,
            sessionId,
            label: "feldman-coefficient-proof",
            participantIndex: dealer.participantIndex,
            coefficientIndex: offset + 1,
        };

        const statement = feldmanCommitments.commitments[offset];
        const proof = await createSchnorrProof(
            coefficient,
            statement,
            group,
            proofContext,
        );

        if (!(await verifySchnorrProof(proof, statement, group, proofContext))) {
            throw new Error("Feldman proof verification failed");
        }
    }

    const recipient = participants.find(
        (participant) => participant.participantIndex !== dealer.participantIndex,
    );

    if (recipient !== undefined) {
        await encryptEnvelope(
            utf8ToBytes(JSON.stringify(shares[recipient.participantIndex - 1])),
            "recipient-public-key",
            {
                sessionId,
                rosterHash,
                phase: 1,
                dealerIndex: dealer.participantIndex,
                recipientIndex: recipient.participantIndex,
                envelopeId: `env-${dealer.participantIndex}-${recipient.participantIndex}`,
                payloadType: "encrypted-dual-share",
                protocolVersion: "v1",
                suite: "X25519",
            },
        );
    }

    void pedersenCommitments;
}
```

At the end of setup, the application derives:

- each participant's final share `x_j` by summing the received secret shares modulo `q`
- the joint public key from the constant Feldman commitments
- each transcript-derived verification key `Y_j` from the published Feldman commitments

The shipped DKG verifier replays this transcript deterministically, checks checkpoint hashes, applies complaint outcomes, and reduces `QUAL` when setup participants are disqualified.

## Encrypt ballots and verify score proofs

The shipped voting surface fixes the valid score domain to `1..10`. Each accepted voter must submit exactly one ballot for every option slot.

```typescript
const jointPublicKey = "derived-joint-public-key";
const validScores = scoreVotingDomain();

const ballots = await Promise.all(
    [7n, 4n, 9n].map(async (vote, offset) => {
        const voterIndex = offset + 1;
        const randomness = BigInt(101 + offset * 103);
        const ciphertext = encryptAdditiveWithRandomness(
            vote,
            jointPublicKey,
            randomness,
            10n,
            group.name,
        );
        const proofContext: ProofContext = {
            protocolVersion: "v1",
            suiteId: group.name,
            manifestHash,
            sessionId,
            label: "ballot-range-proof",
            voterIndex,
            optionIndex: 1,
        };
        const proof = await createDisjunctiveProof(
            vote,
            randomness,
            ciphertext,
            jointPublicKey,
            validScores,
            group,
            proofContext,
        );

        if (
            !(await verifyDisjunctiveProof(
                proof,
                ciphertext,
                jointPublicKey,
                validScores,
                group,
                proofContext,
            ))
        ) {
            throw new Error("Ballot proof verification failed");
        }

        return { voterIndex, ciphertext, proof };
    }),
);
```

## Recompute the aggregate and threshold-decrypt it

Every participant recomputes the aggregate locally from the accepted ballots before producing any decryption share. That same locally recomputed aggregate is what the published-result verifier checks later.

```typescript
const aggregate = ballots
    .map((ballot) => ballot.ciphertext)
    .reduce((accumulator, ciphertext) =>
        addEncryptedValues(accumulator, ciphertext, group.name),
    );

const verifiedAggregate = {
    transcriptHash: "accepted-ballot-transcript-hash",
    ciphertext: aggregate,
};

const thresholdShares: readonly Share[] = [
    /* transcript-derived final share for participant 1 */,
    /* transcript-derived final share for participant 3 */,
];

const decryptionShares = await Promise.all(
    thresholdShares.map(async (share) => {
        const partial = createVerifiedDecryptionShare(
            verifiedAggregate,
            share,
            group,
        );
        const statement: DLEQStatement = {
            publicKey: "transcript-derived-verification-key",
            ciphertext: aggregate,
            decryptionShare: partial.value,
        };
        const proofContext: ProofContext = {
            protocolVersion: "v1",
            suiteId: group.name,
            manifestHash,
            sessionId,
            label: "decryption-share-dleq",
            participantIndex: share.index,
        };
        const proof = await createDLEQProof(
            share.value,
            statement,
            group,
            proofContext,
        );

        if (!(await verifyDLEQProof(proof, statement, group, proofContext))) {
            throw new Error("Decryption-share proof verification failed");
        }

        return partial;
    }),
);

const tally = combineDecryptionShares(aggregate, decryptionShares, group, 30n);
console.log(tally); // 20n
```

## Verify the whole ceremony from the public record

On the safe published path, the application signs typed ballot payloads, typed decryption-share payloads, and one tally-publication payload per option, then calls `verifyElectionCeremonyDetailed(...)` to replay the whole ceremony from the public record.

```typescript
const verified = await verifyElectionCeremonyDetailed({
    protocol: "gjkr",
    manifest,
    sessionId,
    dkgTranscript,
    ballotPayloads,
    decryptionSharePayloads,
    tallyPublications,
});

console.log(verified.qual); // [1, 2, 3]
console.log(verified.perOptionTallies[0]?.tally); // 20n
console.log(verified.boardAudit.overall.fingerprint);
```

The verifier checks the manifest, registrations, acceptances, DKG transcript, locally derived joint public key, ballot proofs, locally recomputed aggregates, decryption shares, tally publications, and board-consistency digests before accepting the result.

## What the tested flow also checks

The end-to-end harness and integration tests do more than the snippets above:

- verify setup, share-distribution, extraction, checkpoint, and tally signatures
- check that local aggregate recomputation is order-independent
- confirm that a truncated or forged aggregate does not match the locally recomputed aggregate
- derive `Y_j` from the Feldman transcript and verify decryption shares against that locally derived key
- verify the same tally with a threshold subset and with all shares
- treat exact duplicate payloads as idempotent retransmissions and conflicting slot re-use as board equivocation
- exercise an AES-GCM complaint path where a malformed dealer envelope disqualifies the dealer and can abort a ceremony
