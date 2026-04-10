import { randomScalarInRange } from '../core/index.js';
import { encodePoint, multiplyBase } from '../core/ristretto.js';

import { resolveElgamalGroup } from './helpers.js';
import type { ElgamalGroupInput, ElgamalParameters } from './types.js';
import { assertValidPrivateKey } from './validation.js';

/**
 * Derives the public key for a caller-supplied private scalar.
 */
export const generateParametersWithPrivateKey = (
    privateKey: bigint,
    group: ElgamalGroupInput,
): ElgamalParameters => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidPrivateKey(privateKey, resolvedGroup);
    const publicKey = encodePoint(multiplyBase(privateKey));

    return {
        group: resolvedGroup,
        publicKey,
        privateKey,
    };
};

/**
 * Generates a fresh ElGamal key pair for the built-in suite.
 */
export const generateParameters = (
    group: ElgamalGroupInput,
): ElgamalParameters => {
    const resolvedGroup = resolveElgamalGroup(group);
    const privateKey = randomScalarInRange(1n, resolvedGroup.q);
    return generateParametersWithPrivateKey(privateKey, resolvedGroup.name);
};
