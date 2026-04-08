import { bytesToBigInt } from '../core/bytes.js';
import {
    InvalidProofError,
    modQ,
    sha256,
    type CryptoGroup,
} from '../core/index.js';
import { bigintToFixedBytes } from '../serialize/index.js';

import type { ProofContext } from './types.js';

const encodeOptionalIndex = (value: number | undefined): bigint | undefined => {
    if (value === undefined) {
        return undefined;
    }

    if (!Number.isInteger(value) || value < 1) {
        throw new InvalidProofError(
            'Proof context indices must be positive integers',
        );
    }

    return BigInt(value);
};

export const assertProofContext = (
    context: ProofContext,
    group: CryptoGroup,
): void => {
    if (context.suiteId !== group.name) {
        throw new InvalidProofError(
            'Proof context suite does not match the selected group',
        );
    }

    if (
        context.protocolVersion.trim() === '' ||
        context.manifestHash.trim() === '' ||
        context.sessionId.trim() === '' ||
        context.label.trim() === ''
    ) {
        throw new InvalidProofError(
            'Proof context requires non-empty version, manifest, session, and label fields',
        );
    }

    encodeOptionalIndex(context.participantIndex);
    encodeOptionalIndex(context.coefficientIndex);
    encodeOptionalIndex(context.voterIndex);
    encodeOptionalIndex(context.optionIndex);
};

export const contextElements = (
    context: ProofContext,
): (bigint | string | Uint8Array)[] => {
    const fields: (bigint | string | Uint8Array)[] = [
        context.protocolVersion,
        context.suiteId,
        context.manifestHash,
        context.sessionId,
        context.label,
    ];

    const optionalFields = [
        encodeOptionalIndex(context.participantIndex),
        encodeOptionalIndex(context.coefficientIndex),
        encodeOptionalIndex(context.voterIndex),
        encodeOptionalIndex(context.optionIndex),
    ];

    for (const field of optionalFields) {
        if (field !== undefined) {
            fields.push(field);
        }
    }

    return fields;
};

export const fixed = (value: bigint, group: CryptoGroup): Uint8Array =>
    bigintToFixedBytes(value, group.byteLength);

export const negateExponent = (value: bigint, q: bigint): bigint =>
    modQ(q - value, q);

export const hashChallenge = async (
    payload: Uint8Array,
    q: bigint,
): Promise<bigint> => modQ(bytesToBigInt(await sha256(payload)), q);

export const sumChallenges = (values: readonly bigint[], q: bigint): bigint =>
    values.reduce((sum, value) => modQ(sum + value, q), 0n);
