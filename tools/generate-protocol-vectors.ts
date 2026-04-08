import { writeFile } from 'node:fs/promises';

import { getGroup, modPowP } from '../src/core/index.js';
import { encryptAdditiveWithRandomness } from '../src/elgamal/index.js';
import {
    createDLEQProof,
    createDisjunctiveProof,
    createSchnorrProof,
    type DLEQStatement,
    type ProofContext,
} from '../src/proofs/index.js';
import {
    canonicalizeElectionManifest,
    deriveSessionId,
    hashElectionManifest,
    verifyAndAggregateBallots,
    type BallotTranscriptEntry,
    type ElectionManifest,
} from '../src/protocol/index.js';
import { createDeterministicSource } from '../tests/helpers/deterministic.js';

const bigintReplacer = (_key: string, value: unknown): unknown =>
    typeof value === 'bigint' ? value.toString() : value;

const buildBallot = async (
    voterIndex: number,
    vote: bigint,
    randomness: bigint,
    publicKey: bigint,
    group = getGroup('ffdhe2048'),
): Promise<BallotTranscriptEntry> => {
    const ciphertext = encryptAdditiveWithRandomness(
        vote,
        publicKey,
        randomness,
        40n,
        group.name,
    );
    const context: ProofContext = {
        protocolVersion: 'v1',
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
            [1n, 2n, 3n, 4n, 5n],
            group,
            context,
            createDeterministicSource(90 + voterIndex, {
                advanceBetweenCalls: false,
            }),
        ),
    };
};

const main = async (): Promise<void> => {
    const group = getGroup('ffdhe2048');
    const manifest: ElectionManifest = {
        protocolVersion: 'v1',
        suiteId: group.name,
        threshold: 3,
        participantCount: 5,
        minimumPublicationThreshold: 4,
        allowAbstention: false,
        scoreDomainMin: 1,
        scoreDomainMax: 10,
        ballotFinality: 'first-valid',
        rosterHash: 'roster-hash',
        optionList: ['Alpha', 'Beta'],
        epochDeadlines: ['2026-04-08T12:00:00Z', '2026-04-08T13:00:00Z'],
    };
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
    const schnorrStatement = modPowP(group.g, schnorrSecret, group.p);
    const schnorrProof = await createSchnorrProof(
        schnorrSecret,
        schnorrStatement,
        group,
        schnorrContext,
        createDeterministicSource(10, {
            advanceBetweenCalls: false,
        }),
    );

    const publicKey = modPowP(group.g, 123n, group.p);
    const ciphertext = encryptAdditiveWithRandomness(
        3n,
        publicKey,
        19n,
        40n,
        group.name,
    );
    const dleqSecret = 17n;
    const dleqStatement: DLEQStatement = {
        publicKey: modPowP(group.g, dleqSecret, group.p),
        ciphertext,
        decryptionShare: modPowP(ciphertext.c1, dleqSecret, group.p),
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
            advanceBetweenCalls: false,
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
        [1n, 2n, 3n, 4n, 5n],
        group,
        disjunctiveContext,
        createDeterministicSource(30, {
            advanceBetweenCalls: false,
        }),
    );

    const ballots = await Promise.all([
        buildBallot(3, 3n, 11n, publicKey, group),
        buildBallot(1, 1n, 7n, publicKey, group),
        buildBallot(2, 2n, 9n, publicKey, group),
    ]);
    const ballotAggregation = await verifyAndAggregateBallots({
        ballots,
        publicKey,
        validValues: [1n, 2n, 3n, 4n, 5n],
        group,
        manifestHash: 'manifest-hash',
        sessionId: 'session-1',
        minimumBallotCount: 2,
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
                    validValues: [1n, 2n, 3n, 4n, 5n],
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
