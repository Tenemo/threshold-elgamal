import { afterEach, describe, expect, it } from 'vitest';

import { createDeterministicSource } from '../../../dev-support/deterministic.js';
import { encodePoint, multiplyBase } from '../../../src/core/ristretto.js';

import {
    fixedBaseModPow,
    multiExponentiate,
    resetBigintMathBackend,
    setBigintMathBackend,
    type BigintMathBackend,
    type MultiExponentiationTerm,
} from '#core';
import {
    addEncryptedValues,
    encryptAdditiveWithRandomness,
    generateParametersWithPrivateKey,
} from '#elgamal';
import {
    createDLEQProof,
    createDisjunctiveProof,
    createSchnorrProof,
    verifyDLEQProof,
    verifyDisjunctiveProof,
    verifySchnorrProof,
    type DLEQStatement,
    type ProofContext,
} from '#proofs';
import { getGroup } from '#root';
import {
    combineDecryptionShares,
    createVerifiedDecryptionShare,
    deriveSharesFromPolynomial,
    type VerifiedAggregateCiphertext,
} from '#threshold';
import { generatePedersenCommitments } from '#vss';

const backendModPow = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    if (modulus === 1n) {
        return 0n;
    }

    let result = 1n;
    let currentBase = ((base % modulus) + modulus) % modulus;
    let currentExponent = exponent;

    while (currentExponent > 0n) {
        if ((currentExponent & 1n) === 1n) {
            result = (result * currentBase) % modulus;
        }
        currentExponent >>= 1n;
        currentBase = (currentBase * currentBase) % modulus;
    }

    return result;
};

const customBackend: BigintMathBackend = {
    modPow: backendModPow,
};

const baseContext = (label: string): ProofContext => ({
    protocolVersion: 'v1',
    suiteId: 'ristretto255',
    manifestHash: 'manifest-hash',
    sessionId: 'session-id',
    label,
});

const computeArtifacts = async (): Promise<{
    readonly aggregate: {
        readonly c1: string;
        readonly c2: string;
    };
    readonly ciphertextLeft: {
        readonly c1: string;
        readonly c2: string;
    };
    readonly ciphertextRight: {
        readonly c1: string;
        readonly c2: string;
    };
    readonly decryptionShares: readonly {
        readonly index: number;
        readonly value: string;
    }[];
    readonly disjunctiveProof: Awaited<
        ReturnType<typeof createDisjunctiveProof>
    >;
    readonly disjunctiveValid: boolean;
    readonly dleqProof: Awaited<ReturnType<typeof createDLEQProof>>;
    readonly dleqValid: boolean;
    readonly fixedBasePower: bigint;
    readonly multiExponentiation: bigint;
    readonly pedersenCommitments: readonly string[];
    readonly schnorrProof: Awaited<ReturnType<typeof createSchnorrProof>>;
    readonly schnorrValid: boolean;
    readonly tally: bigint;
}> => {
    const group = getGroup('ristretto255');
    const secret = 19n;
    const sharePolynomial = [secret, 7n] as const;
    const shares = deriveSharesFromPolynomial(sharePolynomial, 3, group.q);
    const publicKey = generateParametersWithPrivateKey(
        secret,
        group.name,
    ).publicKey;
    const pedersenCommitments = generatePedersenCommitments(
        sharePolynomial,
        [23n, 5n],
        group,
    );

    const ciphertextLeft = encryptAdditiveWithRandomness(
        4n,
        publicKey,
        9n,
        10n,
        group.name,
    );
    const ciphertextRight = encryptAdditiveWithRandomness(
        2n,
        publicKey,
        11n,
        10n,
        group.name,
    );
    const aggregate = addEncryptedValues(
        ciphertextLeft,
        ciphertextRight,
        group.name,
    );
    const verifiedAggregate = {
        transcriptHash: 'aa'.repeat(32),
        ballotCount: 2,
        ciphertext: aggregate,
    } as VerifiedAggregateCiphertext;
    const decryptionShares = shares
        .slice(0, 2)
        .map((share) =>
            createVerifiedDecryptionShare(verifiedAggregate, share, group),
        );
    const tally = combineDecryptionShares(
        aggregate,
        decryptionShares,
        group,
        20n,
    );

    const schnorrContext: ProofContext = {
        ...baseContext('schnorr-proof'),
        participantIndex: 1,
    };
    const schnorrProof = await createSchnorrProof(
        secret,
        publicKey,
        group,
        schnorrContext,
        createDeterministicSource(7),
    );

    const ballotContext: ProofContext = {
        ...baseContext('ballot-range-proof'),
        voterIndex: 1,
        optionIndex: 1,
    };
    const disjunctiveProof = await createDisjunctiveProof(
        4n,
        9n,
        ciphertextLeft,
        publicKey,
        [1n, 2n, 3n, 4n, 5n],
        group,
        ballotContext,
        createDeterministicSource(11),
    );

    const trusteeShare = shares[0];
    const dleqStatement: DLEQStatement = {
        publicKey: encodePoint(multiplyBase(trusteeShare.value)),
        ciphertext: aggregate,
        decryptionShare: decryptionShares[0].value,
    };
    const dleqContext: ProofContext = {
        ...baseContext('decryption-share-dleq'),
        participantIndex: trusteeShare.index,
    };
    const dleqProof = await createDLEQProof(
        trusteeShare.value,
        dleqStatement,
        group,
        dleqContext,
        createDeterministicSource(13),
    );

    const modulus = 97n;
    const multiExponentiationTerms: readonly MultiExponentiationTerm[] = [
        { base: 5n, exponent: 9n },
        { base: 7n, exponent: 4n },
        { base: 11n, exponent: 3n },
    ];

    return {
        ciphertextLeft,
        ciphertextRight,
        aggregate,
        tally,
        pedersenCommitments: pedersenCommitments.commitments,
        fixedBasePower: fixedBaseModPow(5n, 19n, modulus),
        multiExponentiation: multiExponentiate(
            multiExponentiationTerms,
            modulus,
        ),
        schnorrProof,
        schnorrValid: await verifySchnorrProof(
            schnorrProof,
            publicKey,
            group,
            schnorrContext,
        ),
        disjunctiveProof,
        disjunctiveValid: await verifyDisjunctiveProof(
            disjunctiveProof,
            ciphertextLeft,
            publicKey,
            [1n, 2n, 3n, 4n, 5n],
            group,
            ballotContext,
        ),
        dleqProof,
        dleqValid: await verifyDLEQProof(
            dleqProof,
            dleqStatement,
            group,
            dleqContext,
        ),
        decryptionShares,
    };
};

describe('bigint backend injection', () => {
    afterEach(() => {
        resetBigintMathBackend();
    });

    it('preserves deterministic bigint helpers and Ristretto protocol artifacts', async () => {
        const baseline = await computeArtifacts();

        setBigintMathBackend(customBackend);
        const injected = await computeArtifacts();

        expect(injected).toEqual(baseline);
        expect(injected.schnorrValid).toBe(true);
        expect(injected.disjunctiveValid).toBe(true);
        expect(injected.dleqValid).toBe(true);
        expect(injected.tally).toBe(6n);
        expect(injected.fixedBasePower).toBe(38n);
        expect(injected.multiExponentiation).toBe(40n);
    });
});
