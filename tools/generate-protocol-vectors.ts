import { writeFile } from 'node:fs/promises';

import { createDeterministicSource } from '../tests/helpers/deterministic';

import { RISTRETTO_GROUP } from '#core';
import {
    canonicalizeElectionManifest,
    createElectionManifest,
    deriveSessionId,
    hashElectionManifest,
    SHIPPED_PROTOCOL_VERSION,
    type ElectionManifest,
} from '#root';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointMultiply,
} from '#src/core/ristretto';
import { encryptAdditiveWithRandomness } from '#src/elgamal/public';
import {
    createDLEQProof,
    createDisjunctiveProof,
    createSchnorrProof,
    type DLEQStatement,
    type ProofContext,
} from '#src/proofs/public';
import {
    verifyAndAggregateBallots,
    type BallotTranscriptEntry,
} from '#src/protocol/voting-ballot-aggregation';
const bigintReplacer = (_key: string, value: unknown): unknown =>
    typeof value === 'bigint' ? value.toString() : value;
const validScores = Array.from({ length: 10 }, (_value, index) =>
    BigInt(index + 1),
);
const buildBallot = async (
    voterIndex: number,
    vote: bigint,
    randomness: bigint,
    publicKey: string,
    protocolVersion: string,
    group = RISTRETTO_GROUP,
): Promise<BallotTranscriptEntry> => {
    const ciphertext = encryptAdditiveWithRandomness(
        vote,
        publicKey,
        randomness,
        40n,
    );
    const context: ProofContext = {
        protocolVersion,
        suiteId: group.name,
        manifestHash: 'manifest-hash',
        sessionId: 'session-1',
        label: 'ballot-range-proof',
        voterIndex,
        optionIndex: 1,
    };
    return {
        voterIndex,
        optionIndex: 1,
        ciphertext,
        proof: await createDisjunctiveProof(
            vote,
            randomness,
            ciphertext,
            publicKey,
            validScores,
            group,
            context,
            createDeterministicSource(90 + voterIndex, {
                postCallOffset: 17,
            }),
        ),
    };
};
const main = async (): Promise<void> => {
    const group = RISTRETTO_GROUP;
    const manifest: ElectionManifest = createElectionManifest({
        rosterHash: 'roster-hash',
        optionList: ['Alpha', 'Beta'],
    });
    const manifestHash = await hashElectionManifest(manifest);
    const sessionInputs = {
        left: {
            manifestHash,
            rosterHash: 'roster-hash',
            randomNonce: 'nonce:a',
            timestamp: 'timestamp',
        },
        right: {
            manifestHash,
            rosterHash: 'roster-hash',
            randomNonce: 'nonce',
            timestamp: 'a:timestamp',
        },
    } as const;
    const sessionIds = {
        left: await deriveSessionId(
            sessionInputs.left.manifestHash,
            sessionInputs.left.rosterHash,
            sessionInputs.left.randomNonce,
            sessionInputs.left.timestamp,
        ),
        right: await deriveSessionId(
            sessionInputs.right.manifestHash,
            sessionInputs.right.rosterHash,
            sessionInputs.right.randomNonce,
            sessionInputs.right.timestamp,
        ),
    };
    const schnorrContext: ProofContext = {
        protocolVersion: 'v1',
        suiteId: group.name,
        manifestHash,
        sessionId: sessionIds.left,
        label: 'vector-schnorr',
        participantIndex: 1,
        coefficientIndex: 1,
    };
    const schnorrSecret = 77n;
    const schnorrStatement = encodePoint(multiplyBase(schnorrSecret));
    const schnorrProof = await createSchnorrProof(
        schnorrSecret,
        schnorrStatement,
        group,
        schnorrContext,
        createDeterministicSource(10, {
            postCallOffset: 17,
        }),
    );
    const publicKey = encodePoint(multiplyBase(123n));
    const ciphertext = encryptAdditiveWithRandomness(3n, publicKey, 19n, 40n);
    const dleqSecret = 17n;
    const dleqStatement: DLEQStatement = {
        publicKey: encodePoint(multiplyBase(dleqSecret)),
        ciphertext,
        decryptionShare: encodePoint(
            pointMultiply(decodePoint(ciphertext.c1), dleqSecret),
        ),
    };
    const dleqContext: ProofContext = {
        protocolVersion: 'v1',
        suiteId: group.name,
        manifestHash,
        sessionId: sessionIds.left,
        label: 'vector-dleq',
        participantIndex: 2,
    };
    const dleqProof = await createDLEQProof(
        dleqSecret,
        dleqStatement,
        group,
        dleqContext,
        createDeterministicSource(20, {
            postCallOffset: 17,
        }),
    );
    const disjunctiveContext: ProofContext = {
        protocolVersion: 'v1',
        suiteId: group.name,
        manifestHash: 'manifest-hash',
        sessionId: 'session-1',
        label: 'ballot-range-proof',
        voterIndex: 1,
        optionIndex: 1,
    };
    const disjunctiveProof = await createDisjunctiveProof(
        3n,
        19n,
        ciphertext,
        publicKey,
        validScores,
        group,
        disjunctiveContext,
        createDeterministicSource(30, {
            postCallOffset: 17,
        }),
    );
    const ballots = await Promise.all([
        buildBallot(3, 3n, 11n, publicKey, SHIPPED_PROTOCOL_VERSION, group),
        buildBallot(1, 1n, 7n, publicKey, SHIPPED_PROTOCOL_VERSION, group),
        buildBallot(2, 2n, 9n, publicKey, SHIPPED_PROTOCOL_VERSION, group),
    ]);
    const ballotAggregation = await verifyAndAggregateBallots({
        ballots,
        publicKey,
        validValues: validScores,
        protocolVersion: SHIPPED_PROTOCOL_VERSION,
        manifestHash: 'manifest-hash',
        sessionId: 'session-1',
    });
    await writeFile(
        new URL('../test-vectors/protocol.json', import.meta.url),
        `${JSON.stringify(
            {
                group: group.name,
                manifest,
                canonicalManifest: canonicalizeElectionManifest(manifest),
                manifestHash,
                sessionInputs,
                sessionIds,
                schnorr: {
                    secret: schnorrSecret,
                    statement: schnorrStatement,
                    context: schnorrContext,
                    proof: schnorrProof,
                },
                dleq: {
                    secret: dleqSecret,
                    statement: dleqStatement,
                    context: dleqContext,
                    proof: dleqProof,
                },
                disjunctive: {
                    publicKey,
                    plaintext: 3n,
                    randomness: 19n,
                    ciphertext,
                    validValues: validScores,
                    context: disjunctiveContext,
                    proof: disjunctiveProof,
                },
                ballotAggregation,
            },
            bigintReplacer,
            2,
        )}\n`,
        'utf8',
    );
    console.log('Generated protocol test vectors.');
};
void main();
