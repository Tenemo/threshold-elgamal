import { hexToBytes } from '../core/bytes';
import {
    assertInSubgroupOrIdentity,
    assertScalarInZq,
    assertValidPublicKey,
    IndexOutOfRangeError,
    InvalidShareError,
    PlaintextDomainError,
    RISTRETTO_GROUP,
    modInvQ,
    modQ,
} from '../core/index';
import {
    decodePoint,
    encodePoint,
    hashChallengeToScalar,
    pointAdd,
    pointMultiply,
    pointSubtract,
    RISTRETTO_ZERO,
} from '../core/ristretto';
import {
    addEncryptedValues,
    encryptAdditiveWithRandomness,
} from '../elgamal/additive';
import { babyStepGiantStep } from '../elgamal/bsgs';
import type { ElGamalCiphertext } from '../elgamal/types';
import { encodeForChallenge } from '../serialize/encoding';

import {
    createVerifiedAggregateCiphertext,
    type AggregateDecryptionPreparationInput,
    type DecryptionShare,
    type Share,
} from './types';

const DECRYPTION_RERANDOMIZATION_DOMAIN =
    'threshold-elgamal/decryption-rerandomization';

const assertPositiveIndex = (index: number, label: string): void => {
    if (!Number.isInteger(index) || index < 1) {
        throw new IndexOutOfRangeError(
            `${label} index must be a positive integer`,
        );
    }
};

const assertNonEmptyString = (value: string, label: string): void => {
    if (value.trim() === '') {
        throw new InvalidShareError(`${label} must be a non-empty string`);
    }
};

const assertUniqueIndices = (
    indices: readonly number[],
    label: string,
): void => {
    const seen = new Set<number>();

    for (const index of indices) {
        if (seen.has(index)) {
            throw new InvalidShareError(`${label} indices must be unique`);
        }
        seen.add(index);
    }
};

const assertVerifiedAggregate = (
    aggregate: AggregateDecryptionPreparationInput['aggregate'],
): void => {
    assertNonEmptyString(aggregate.transcriptHash, 'Aggregate transcript hash');
    if (!Number.isInteger(aggregate.ballotCount) || aggregate.ballotCount < 1) {
        throw new InvalidShareError(
            'Verified aggregate ciphertext requires at least one accepted ballot',
        );
    }
    assertInSubgroupOrIdentity(aggregate.ciphertext.c1);
    assertInSubgroupOrIdentity(aggregate.ciphertext.c2);
};

const decryptionRerandomizationScalar = (
    input: AggregateDecryptionPreparationInput,
): bigint =>
    1n +
    (hashChallengeToScalar(
        encodeForChallenge(
            DECRYPTION_RERANDOMIZATION_DOMAIN,
            input.protocolVersion,
            input.manifestHash,
            input.sessionId,
            input.aggregate.transcriptHash,
            BigInt(input.aggregate.ballotCount),
            BigInt(input.optionIndex),
            hexToBytes(input.publicKey),
            hexToBytes(input.aggregate.ciphertext.c1),
            hexToBytes(input.aggregate.ciphertext.c2),
        ),
    ) %
        (RISTRETTO_GROUP.q - 1n));

/**
 * Computes the Lagrange coefficient for `participantIndex` at `x = 0`.
 *
 * @param participantIndex Target share index as a bigint.
 * @param allIndices Full subset of indices participating in reconstruction.
 * @param q Prime-order subgroup order.
 * @returns `lambda_i mod q`.
 */
export const lagrangeCoefficient = (
    participantIndex: bigint,
    allIndices: readonly bigint[],
    q: bigint,
): bigint => {
    let numerator = 1n;
    let denominator = 1n;

    for (const otherIndex of allIndices) {
        if (otherIndex === participantIndex) {
            continue;
        }

        numerator = modQ(numerator * otherIndex, q);
        denominator = modQ(
            denominator * modQ(otherIndex - participantIndex, q),
            q,
        );
    }

    return modQ(numerator * modInvQ(denominator, q), q);
};

/**
 * Creates a partial decryption share `d_i = x_i C_1`.
 */
export const createDecryptionShare = (
    ciphertext: ElGamalCiphertext,
    share: Share,
): DecryptionShare => {
    assertPositiveIndex(share.index, 'Share');
    assertScalarInZq(share.value, RISTRETTO_GROUP.q);
    assertInSubgroupOrIdentity(ciphertext.c1);

    return {
        index: share.index,
        value: encodePoint(
            pointMultiply(decodePoint(ciphertext.c1), share.value),
        ),
    };
};

/**
 * Prepares a verified aggregate for decryption.
 *
 * When the accepted aggregate has identity `c1`, the raw DLEQ statement would
 * degenerate because every participant would obtain the same identity-valued
 * partial share. This helper deterministically adds a public encryption of zero
 * in that corner case so the plaintext stays unchanged while the decryption
 * proof statement remains meaningful.
 */
export const prepareAggregateForDecryption = (
    input: AggregateDecryptionPreparationInput,
): AggregateDecryptionPreparationInput['aggregate'] => {
    assertVerifiedAggregate(input.aggregate);
    assertValidPublicKey(input.publicKey);
    assertNonEmptyString(input.protocolVersion, 'Protocol version');
    assertNonEmptyString(input.manifestHash, 'Manifest hash');
    assertNonEmptyString(input.sessionId, 'Session id');
    assertPositiveIndex(input.optionIndex, 'Option');

    if (!decodePoint(input.aggregate.ciphertext.c1).is0()) {
        return input.aggregate;
    }

    const rerandomizedCiphertext = addEncryptedValues(
        input.aggregate.ciphertext,
        encryptAdditiveWithRandomness(
            0n,
            input.publicKey,
            decryptionRerandomizationScalar(input),
            0n,
        ),
    );

    return createVerifiedAggregateCiphertext(
        input.aggregate.transcriptHash,
        rerandomizedCiphertext,
        input.aggregate.ballotCount,
    );
};

/**
 * Combines indexed decryption shares via Lagrange interpolation at `x = 0`.
 */
export const combineDecryptionShares = (
    ciphertext: ElGamalCiphertext,
    decryptionShares: readonly DecryptionShare[],
    bound: bigint,
): bigint => {
    if (decryptionShares.length === 0) {
        throw new InvalidShareError(
            'At least one decryption share is required for reconstruction',
        );
    }

    assertInSubgroupOrIdentity(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);

    const indices = decryptionShares.map((share) => {
        assertPositiveIndex(share.index, 'Decryption share');
        assertInSubgroupOrIdentity(share.value);
        return share.index;
    });

    assertUniqueIndices(indices, 'Decryption share');

    const bigintIndices = indices.map((index) => BigInt(index));
    let combinedFactor = RISTRETTO_ZERO;

    for (const share of decryptionShares) {
        const lambda = lagrangeCoefficient(
            BigInt(share.index),
            bigintIndices,
            RISTRETTO_GROUP.q,
        );
        combinedFactor = pointAdd(
            combinedFactor,
            pointMultiply(
                decodePoint(share.value),
                modQ(lambda, RISTRETTO_GROUP.q),
            ),
        );
    }

    const encodedMessage = pointSubtract(
        decodePoint(ciphertext.c2),
        combinedFactor,
    );
    const message = babyStepGiantStep(
        encodePoint(encodedMessage),
        RISTRETTO_GROUP.g,
        bound,
    );

    if (message === null) {
        throw new PlaintextDomainError(
            'Threshold decryption result exceeds the supplied additive bound',
        );
    }

    return message;
};
