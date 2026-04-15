import { performance } from 'node:perf_hooks';

import { RISTRETTO_GROUP, utf8ToBytes } from '#core';
import {
    createDisjunctiveProof,
    createSchnorrProof,
    decryptEnvelope,
    encryptAdditiveWithRandomness,
    encryptEnvelope,
    exportTransportPublicKey,
    generateTransportKeyPair,
    verifyDisjunctiveProof,
    verifySchnorrProof,
    type ProofContext,
} from '#root';
import { encodePoint, multiplyBase } from '#src/core/ristretto';

type BenchmarkRow = {
    readonly averageMs: number;
    readonly iterations: number;
    readonly name: string;
    readonly totalMs: number;
};
const round = (value: number): number => Math.round(value * 1000) / 1000;
const measure = async (
    name: string,
    iterations: number,
    task: () => Promise<void> | void,
): Promise<BenchmarkRow> => {
    await task();
    const start = performance.now();
    for (let index = 0; index < iterations; index += 1) {
        await task();
    }
    const totalMs = performance.now() - start;
    return {
        name,
        iterations,
        totalMs: round(totalMs),
        averageMs: round(totalMs / iterations),
    };
};
const main = async (): Promise<void> => {
    const group = RISTRETTO_GROUP;
    const publicKey = encodePoint(multiplyBase(123n));
    const schnorrStatement = encodePoint(multiplyBase(77n));
    const proofContext: ProofContext = {
        protocolVersion: 'v1',
        suiteId: 'ristretto255',
        manifestHash: 'manifest-hash',
        sessionId: 'session-bench',
        label: 'bench-proof',
        participantIndex: 1,
        optionIndex: 1,
    };
    const schnorrProof = await createSchnorrProof(
        77n,
        schnorrStatement,
        group,
        proofContext,
    );
    const ciphertext = encryptAdditiveWithRandomness(3n, publicKey, 19n, 40n);
    const disjunctiveProof = await createDisjunctiveProof(
        3n,
        19n,
        ciphertext,
        publicKey,
        [1n, 2n, 3n, 4n, 5n],
        group,
        proofContext,
    );
    const recipient = await generateTransportKeyPair();
    const recipientPublicKey = await exportTransportPublicKey(
        recipient.publicKey,
    );
    const envelopeContext = {
        sessionId: 'session-bench',
        phase: 1,
        dealerIndex: 1,
        recipientIndex: 2,
        envelopeId: 'env-1-2',
        payloadType: 'dkg-share',
        protocolVersion: 'v1',
        rosterHash: 'roster-hash',
        suite: 'X25519' as const,
    };
    const envelopePlaintext = utf8ToBytes('benchmark-envelope');
    const encrypted = await encryptEnvelope(
        envelopePlaintext,
        recipientPublicKey,
        envelopeContext,
    );
    const rows = await Promise.all([
        measure('createSchnorrProof', 40, async () => {
            await createSchnorrProof(
                77n,
                schnorrStatement,
                group,
                proofContext,
            );
        }),
        measure('verifySchnorrProof', 80, async () => {
            await verifySchnorrProof(
                schnorrProof,
                schnorrStatement,
                group,
                proofContext,
            );
        }),
        measure('verifyDisjunctiveProof', 20, async () => {
            await verifyDisjunctiveProof(
                disjunctiveProof,
                ciphertext,
                publicKey,
                [1n, 2n, 3n, 4n, 5n],
                group,
                proofContext,
            );
        }),
        measure('encryptEnvelope', 20, async () => {
            await encryptEnvelope(
                envelopePlaintext,
                recipientPublicKey,
                envelopeContext,
            );
        }),
        measure('decryptEnvelope', 20, async () => {
            await decryptEnvelope(encrypted.envelope, recipient.privateKey);
        }),
    ]);
    console.table(rows);
};
void main();
