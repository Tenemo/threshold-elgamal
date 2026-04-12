import { hexToBytes } from '../core/bytes';
import {
    assertCanonicalRistrettoGroup,
    InvalidProofError,
    modQ,
    type CryptoGroup,
} from '../core/index';
import { encodeScalar, hashChallengeToScalar } from '../core/ristretto';

import type { ProofContext } from './types';

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
    try {
        assertCanonicalRistrettoGroup(group, 'Proof group');
    } catch (error) {
        throw new InvalidProofError(
            error instanceof Error ? error.message : String(error),
        );
    }

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
        ['participant-index', encodeOptionalIndex(context.participantIndex)],
        ['coefficient-index', encodeOptionalIndex(context.coefficientIndex)],
        ['voter-index', encodeOptionalIndex(context.voterIndex)],
        ['option-index', encodeOptionalIndex(context.optionIndex)],
    ] as const;

    for (const [label, field] of optionalFields) {
        fields.push(`proof-context/${label}`);
        fields.push(field === undefined ? 0n : 1n);
        if (field !== undefined) {
            fields.push(field);
        }
    }

    return fields;
};

export const fixedPoint = (value: string): Uint8Array => hexToBytes(value);

export const fixedScalar = (value: bigint, group: CryptoGroup): Uint8Array => {
    void group;
    return hexToBytes(encodeScalar(value));
};

export const hashChallenge = (
    payload: Uint8Array,
    q: bigint,
): Promise<bigint> => Promise.resolve(modQ(hashChallengeToScalar(payload), q));

export const sumChallenges = (values: readonly bigint[], q: bigint): bigint =>
    values.reduce((sum, value) => modQ(sum + value, q), 0n);
