import { modPowP, randomScalarInRange } from '../core/index.js';

import { resolveElgamalGroup } from './helpers.js';
import type { ElgamalGroupInput, ElgamalParameters } from './types.js';
import { assertValidPrivateKey } from './validation.js';

/**
 * Derives the public key for a caller-supplied private scalar.
 *
 * @param privateKey Private scalar in the range `1..q-1`.
 * @param group Built-in group identifier that fixes `(p, q, g, h)`.
 * @returns Key material containing the resolved group, public key, and private key.
 *
 * @throws `InvalidScalarError` When `privateKey` is outside `1..q-1`.
 * @throws `UnsupportedSuiteError` When `group` does not resolve to a built-in suite.
 *
 * @example
 * ```ts
 * const params = generateParametersWithPrivateKey(12345n, 'ffdhe3072');
 * ```
 */
export const generateParametersWithPrivateKey = (
    privateKey: bigint,
    group: ElgamalGroupInput,
): ElgamalParameters => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidPrivateKey(privateKey, resolvedGroup);
    const publicKey = modPowP(resolvedGroup.g, privateKey, resolvedGroup.p);

    return {
        group: resolvedGroup,
        publicKey,
        privateKey,
    };
};

/**
 * Generates a fresh ElGamal key pair for a built-in group.
 *
 * @param group Built-in group identifier that fixes `(p, q, g, h)`.
 * @returns Key material containing the resolved group, public and private keys.
 *
 * @throws `UnsupportedSuiteError` When `group` does not resolve to a built-in suite.
 *
 * @example
 * ```ts
 * const { publicKey, privateKey, group } = generateParameters('ffdhe3072');
 * ```
 */
export const generateParameters = (
    group: ElgamalGroupInput,
): ElgamalParameters => {
    const resolvedGroup = resolveElgamalGroup(group);
    const privateKey = randomScalarInRange(1n, resolvedGroup.q);
    return generateParametersWithPrivateKey(privateKey, resolvedGroup.name);
};
