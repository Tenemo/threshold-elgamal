import {
    assertValidParticipantIndex,
    getGroup,
    modInvP,
    modP,
    modPowP,
} from '../core/index.js';
import type { GroupName } from '../core/types.js';
import { encryptAdditiveWithRandomness } from '../elgamal/additive.js';
import { babyStepGiantStep } from '../elgamal/bsgs.js';

import { combineDecryptionShares, createDecryptionShare } from './decrypt.js';
import { lagrangeCoefficient } from './lagrange.js';
import { deriveSharesFromPolynomial } from './shares.js';

type ThresholdVectorConfig = {
    readonly bound: bigint;
    readonly groupName: GroupName;
    readonly message: bigint;
    readonly participantCount: number;
    readonly polynomial: readonly bigint[];
    readonly randomness: bigint;
    readonly subsetIndices: readonly number[];
};

type ThresholdVectorRecord = {
    readonly ciphertext: {
        readonly bound: bigint;
        readonly c1: bigint;
        readonly c2: bigint;
        readonly message: bigint;
        readonly randomness: bigint;
    };
    readonly combinedFactor: bigint;
    readonly decryptionShares: readonly {
        readonly index: number;
        readonly value: bigint;
    }[];
    readonly encodedMessage: bigint;
    readonly group: GroupName;
    readonly lagrangeCoefficients: readonly {
        readonly index: number;
        readonly value: bigint;
    }[];
    readonly participantCount: number;
    readonly participantPublicKeys: readonly {
        readonly index: number;
        readonly value: bigint;
    }[];
    readonly polynomial: readonly bigint[];
    readonly publicKey: bigint;
    readonly recovered: bigint;
    readonly shares: readonly {
        readonly index: number;
        readonly value: bigint;
    }[];
    readonly subsetIndices: readonly number[];
    readonly threshold: number;
};

const assertVectorConfig = (config: ThresholdVectorConfig): void => {
    const threshold = config.polynomial.length;

    if (config.polynomial.length === 0) {
        throw new Error(
            'Threshold vector generation requires a non-empty polynomial',
        );
    }

    if (config.participantCount < threshold) {
        throw new Error(
            'Threshold vector participant count must be at least the threshold',
        );
    }

    if (config.subsetIndices.length < threshold) {
        throw new Error(
            'Threshold vector subset must contain at least threshold many shares',
        );
    }

    const seenSubsetIndices = new Set<number>();
    for (const subsetIndex of config.subsetIndices) {
        assertValidParticipantIndex(subsetIndex, config.participantCount);
        if (seenSubsetIndices.has(subsetIndex)) {
            throw new Error(
                `Threshold vector subset indices must be unique; duplicate index ${subsetIndex} encountered`,
            );
        }
        seenSubsetIndices.add(subsetIndex);
    }
};

export const generateThresholdVectorRecord = (
    config: ThresholdVectorConfig,
): ThresholdVectorRecord => {
    assertVectorConfig(config);

    const group = getGroup(config.groupName);
    const threshold = config.polynomial.length;
    const shares = deriveSharesFromPolynomial(
        config.polynomial,
        config.participantCount,
        group.q,
    );
    const publicKey = modPowP(group.g, config.polynomial[0], group.p);
    const participantPublicKeys = shares.map((share) => ({
        index: share.index,
        value: modPowP(group.g, share.value, group.p),
    }));
    const ciphertext = encryptAdditiveWithRandomness(
        config.message,
        publicKey,
        config.randomness,
        config.bound,
        group.name,
    );
    const subsetShares = shares.filter((share) =>
        config.subsetIndices.includes(share.index),
    );
    const decryptionShares = subsetShares.map((share) =>
        createDecryptionShare(ciphertext, share, group),
    );
    const lagrangeCoefficients = config.subsetIndices.map((index) => ({
        index,
        value: lagrangeCoefficient(
            BigInt(index),
            config.subsetIndices.map((item) => BigInt(item)),
            group.q,
        ),
    }));

    let combinedFactor = 1n;

    for (const decryptionShare of decryptionShares) {
        const lambda = lagrangeCoefficients.find(
            (item) => item.index === decryptionShare.index,
        );

        if (lambda === undefined) {
            throw new Error(
                `Missing Lagrange coefficient for share ${decryptionShare.index}`,
            );
        }

        combinedFactor = modP(
            combinedFactor *
                modPowP(decryptionShare.value, lambda.value, group.p),
            group.p,
        );
    }

    const encodedMessage = modP(
        ciphertext.c2 * modInvP(combinedFactor, group.p),
        group.p,
    );
    const recovered = combineDecryptionShares(
        ciphertext,
        decryptionShares,
        group,
        config.bound,
    );

    if (recovered !== config.message) {
        throw new Error('Generated threshold vector does not round-trip');
    }

    const discreteLog = babyStepGiantStep(
        encodedMessage,
        group.g,
        group.p,
        config.bound,
    );
    if (discreteLog !== config.message) {
        throw new Error('Generated threshold vector encoded message mismatch');
    }

    return {
        group: group.name,
        threshold,
        participantCount: config.participantCount,
        polynomial: config.polynomial,
        publicKey,
        participantPublicKeys,
        shares,
        ciphertext: {
            ...ciphertext,
            message: config.message,
            randomness: config.randomness,
            bound: config.bound,
        },
        subsetIndices: config.subsetIndices,
        decryptionShares,
        lagrangeCoefficients,
        combinedFactor,
        encodedMessage,
        recovered,
    };
};
