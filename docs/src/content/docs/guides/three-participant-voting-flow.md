---
title: Three-participant voting flow
description: A complete signed and verified 3-participant voting flow from setup through tally publication.
sidebar:
  order: 3
---

This guide shows a full 3-participant flow for the current shipped surface:

- roster freeze, manifest hashing, and signed setup payloads
- GJKR-style setup material with Pedersen commitments, encrypted shares, and
  Feldman extraction proofs
- additive ballots with disjunctive proofs
- local aggregate recomputation
- threshold decryption shares with DLEQ proofs
- typed ballot, decryption-share, and tally payloads on the safe protocol path

The complete tested version lives in
`tests/node/integration/voting-flow-harness.ts`. The snippets below keep the same
structure but omit repeated helper boilerplate.

## Imports and helper style

```typescript
import { getGroup, modP, modPowP, modQ, sha256, utf8ToBytes } from "threshold-elgamal/core";
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
    canonicalUnsignedPayloadBytes,
    canonicalizeJson,
    deriveSessionId,
    hashElectionManifest,
    hashRosterEntries,
    hashProtocolTranscript,
    verifyPublishedVotingResult,
    type ElectionManifest,
    type ProtocolPayload,
    type SignedPayload,
} from "threshold-elgamal/protocol";
import { bytesToHex, fixedHexToBigint } from "threshold-elgamal/serialize";
import {
    combineDecryptionShares,
    createVerifiedDecryptionShare,
    type Share,
} from "threshold-elgamal/threshold";
import {
    decryptEnvelope,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPrivateKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    signPayloadBytes,
    verifyPayloadSignature,
} from "threshold-elgamal/transport";
import {
    derivePedersenShares,
    generateFeldmanCommitments,
    generatePedersenCommitments,
} from "threshold-elgamal/vss";

const hashJson = async (value: unknown, bigintByteLength?: number): Promise<string> =>
    bytesToHex(
        await sha256(
            utf8ToBytes(
                canonicalizeJson(value as never, {
                    bigintByteLength,
                }),
            ),
        ),
    );

const signProtocolPayload = async <TPayload extends ProtocolPayload>(
    privateKey: CryptoKey,
    payload: TPayload,
): Promise<SignedPayload<TPayload>> => ({
    payload,
    signature: await signPayloadBytes(
        privateKey,
        canonicalUnsignedPayloadBytes(payload),
    ),
});
```

## Freeze the roster and collect setup signatures

The library ships `hashRosterEntries()`, so the application can freeze the
setup roster before building the manifest and signing the phase-0 payloads.

```typescript
const group = getGroup("ffdhe2048");
const participants = await Promise.all(
    [1, 2, 3].map(async (index) => {
        const auth = await generateAuthKeyPair();
        const transport = await generateTransportKeyPair("P-256");

        return {
            index,
            auth,
            authPublicKeyHex: await exportAuthPublicKey(auth.publicKey),
            transportPublicKeyHex: await exportTransportPublicKey(
                transport.publicKey,
            ),
            transportPrivateKeyHex: await exportTransportPrivateKey(
                transport.privateKey,
            ),
        };
    }),
);

const rosterHash = await hashRosterEntries(
    participants.map((participant) => ({
        participantIndex: participant.index,
        authPublicKey: participant.authPublicKeyHex,
        transportPublicKey: participant.transportPublicKeyHex,
    })),
);

const manifest: ElectionManifest = {
    protocolVersion: "v1",
    suiteId: group.name,
    threshold: 2,
    participantCount: 3,
    minimumPublicationThreshold: 3,
    allowAbstention: false,
    scoreDomainMin: 1,
    scoreDomainMax: 10,
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

Each participant then signs a registration payload and a manifest-acceptance
payload. The integration test verifies every signature with
`verifyPayloadSignature()`.

## Build the setup transcript

For a 2-of-3 example, each participant uses a degree-1 secret polynomial and a
matching degree-1 blinding polynomial.

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
    const pedersenShares = derivePedersenShares(
        dealer.secretPolynomial,
        dealer.blindingPolynomial,
        3,
        group.q,
    );
    const feldmanCommitments = generateFeldmanCommitments(
        dealer.secretPolynomial,
        group,
    );

    for (const [coefficientIndex, coefficient] of dealer.secretPolynomial.entries()) {
        const proofCoefficientIndex = coefficientIndex + 1;
        const statement = feldmanCommitments.commitments[coefficientIndex];
        const proofContext: ProofContext = {
            protocolVersion: "v1",
            suiteId: group.name,
            manifestHash,
            sessionId,
            label: "feldman-coefficient-proof",
            participantIndex: dealer.participantIndex,
            coefficientIndex: proofCoefficientIndex,
        };
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

    for (const recipient of participants.filter(
        (participant) => participant.index !== dealer.participantIndex,
    )) {
        const share = pedersenShares[recipient.index - 1];
        const plaintext = utf8ToBytes(
            canonicalizeJson(
                {
                    index: recipient.index,
                    secretValue: share.secretValue,
                    blindingValue: share.blindingValue,
                },
                {
                    bigintByteLength: group.byteLength,
                },
            ),
        );
        const { envelope } = await encryptEnvelope(
            plaintext,
            recipient.transportPublicKeyHex,
            {
                sessionId,
                rosterHash,
                phase: 1,
                dealerIndex: dealer.participantIndex,
                recipientIndex: recipient.index,
                envelopeId: `env-${dealer.participantIndex}-${recipient.index}`,
                payloadType: "encrypted-dual-share",
                protocolVersion: "v1",
                suite: "P-256",
            },
        );

        const decrypted = await decryptEnvelope(
            envelope,
            recipient.transportPrivateKeyHex,
        );
        const decoded = JSON.parse(new TextDecoder().decode(decrypted)) as {
            blindingValue: string;
            index: number;
            secretValue: string;
        };

        if (fixedHexToBigint(decoded.secretValue) !== share.secretValue) {
            throw new Error("Encrypted share mismatch");
        }
    }
}
```

At the end of setup, the application derives:

- each participant's final share `x_j` by summing the received secret shares
  modulo `q`
- the joint public key by multiplying the constant Feldman commitments
- each transcript-derived verification key `Y_j` from the published Feldman
  commitments

The integration test then feeds the signed setup payloads through the shipped
GJKR reducer and expects a completed `QUAL = [1, 2, 3]`.

## Encrypt ballots and verify score proofs

The current library ships typed ballot, decryption-share, and tally payload
schemas together with high-level published-result verifiers. Use
`verifyPublishedVotingResult()` for a single-option manifest or
`verifyPublishedVotingResults()` for per-option verification across a
multi-option manifest. The ballot-level cryptography is still available directly
when you need to stage or inspect intermediate artifacts.

```typescript
const jointPublicKey = /* product of A_i,0 from the setup transcript */;
const validScores = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n] as const;

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

        return {
            voterIndex,
            ciphertext,
            proof,
        };
    }),
);
```

## Recompute the aggregate and threshold-decrypt it

Every participant recomputes the aggregate locally from the accepted ballots.
That aggregate is then anchored to the accepted ballot log hash before any
decryption share is produced.

```typescript
const aggregate = ballots
    .map((ballot) => ballot.ciphertext)
    .reduce(
        (accumulator, ciphertext) =>
            addEncryptedValues(accumulator, ciphertext, group.name),
        { c1: 1n, c2: 1n },
    );

const ballotLogHash = await hashJson(
    ballots.map((ballot) => ({
        voterIndex: ballot.voterIndex,
        ciphertext: ballot.ciphertext,
        proof: ballot.proof,
    })),
    group.byteLength,
);

const verifiedAggregate = {
    transcriptHash: ballotLogHash,
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
            publicKey: /* transcript-derived Y_j */,
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

On the safe published path, the application signs typed ballot payloads,
typed decryption-share payloads, and one tally-publication payload per option,
then calls `verifyPublishedVotingResult()` for a single-option manifest or
`verifyPublishedVotingResults()` for a multi-option manifest. The verifier
replays the DKG log, recomputes the ballot aggregate locally, verifies the DLEQ
proofs, and checks the announced tally before accepting it.

## What the integration test also checks

The tested end-to-end flow does more than the snippets above:

- verifies every setup, share-distribution, extraction, and confirmation
  signature
- checks that local aggregate recomputation is order-independent
- confirms that a truncated aggregate does not match the locally recomputed
  aggregate
- derives `Y_j` from the Feldman transcript and checks that it equals `g^{x_j}`
- verifies the same tally with a threshold subset and with all shares
- exercises an AES-GCM complaint path where a malformed dealer envelope
  disqualifies the dealer and aborts a 3-of-3 ceremony

