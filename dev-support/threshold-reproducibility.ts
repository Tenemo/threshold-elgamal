import { assertValidParticipantIndex, getGroup } from '#core';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointAdd,
    pointMultiply,
    pointSubtract,
    RISTRETTO_ZERO,
} from '#src/core/ristretto';
import type { EncodedPoint, GroupIdentifier, GroupName } from '#src/core/types';
import { encryptAdditiveWithRandomness } from '#src/elgamal/additive';
import { babyStepGiantStep } from '#src/elgamal/bsgs';
import {
    combineDecryptionShares,
    createDecryptionShare,
} from '#src/threshold/decrypt';
import { lagrangeCoefficient } from '#src/threshold/lagrange';
import { deriveSharesFromPolynomial } from '#src/threshold/shares';
type ThresholdVectorConfig = {
    readonly bound: bigint;
    readonly groupName: GroupIdentifier;
    readonly message: bigint;
    readonly participantCount: number;
    readonly polynomial: readonly bigint[];
    readonly randomness: bigint;
    readonly subsetIndices: readonly number[];
};
type ThresholdVectorRecord = {
    readonly ciphertext: {
        readonly bound: bigint;
        readonly c1: string;
        readonly c2: string;
        readonly message: bigint;
        readonly randomness: bigint;
    };
    readonly combinedFactor: string;
    readonly decryptionShares: readonly {
        readonly index: number;
        readonly value: string;
    }[];
    readonly encodedMessage: string;
    readonly group: GroupName;
    readonly lagrangeCoefficients: readonly {
        readonly index: number;
        readonly value: bigint;
    }[];
    readonly participantCount: number;
    readonly participantPublicKeys: readonly {
        readonly index: number;
        readonly value: EncodedPoint;
    }[];
    readonly polynomial: readonly bigint[];
    readonly publicKey: EncodedPoint;
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
    const publicKey = encodePoint(multiplyBase(config.polynomial[0]));
    const participantPublicKeys = shares.map((share) => ({
        index: share.index,
        value: encodePoint(multiplyBase(share.value)),
    }));
    const ciphertext = encryptAdditiveWithRandomness(
        config.message,
        publicKey,
        config.randomness,
        config.bound,
    );
    const subsetShares = shares.filter((share) =>
        config.subsetIndices.includes(share.index),
    );
    const decryptionShares = subsetShares.map((share) =>
        createDecryptionShare(ciphertext, share),
    );
    const lagrangeCoefficients = config.subsetIndices.map((index) => ({
        index,
        value: lagrangeCoefficient(
            BigInt(index),
            config.subsetIndices.map((item) => BigInt(item)),
            group.q,
        ),
    }));
    let combinedFactor = RISTRETTO_ZERO;
    for (const decryptionShare of decryptionShares) {
        const lambda = lagrangeCoefficients.find(
            (item) => item.index === decryptionShare.index,
        );
        if (lambda === undefined) {
            throw new Error(
                `Missing Lagrange coefficient for share ${decryptionShare.index}`,
            );
        }
        combinedFactor = pointAdd(
            combinedFactor,
            pointMultiply(decodePoint(decryptionShare.value), lambda.value),
        );
    }
    const encodedMessage = encodePoint(
        pointSubtract(decodePoint(ciphertext.c2), combinedFactor),
    );
    const recovered = combineDecryptionShares(
        ciphertext,
        decryptionShares,
        config.bound,
    );
    if (recovered !== config.message) {
        throw new Error('Generated threshold vector does not round-trip');
    }
    const discreteLog = babyStepGiantStep(
        encodedMessage,
        group.g,
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
        combinedFactor: encodePoint(combinedFactor),
        encodedMessage,
        recovered,
    };
};
