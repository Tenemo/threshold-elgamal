import { randomScalarInRange, RISTRETTO_GROUP } from '../core/index.js';
import { encodePoint, multiplyBase } from '../core/ristretto.js';

import type { ElgamalKeyPair } from './types.js';
import { assertValidPrivateKey } from './validation.js';

/**
 * Derives the public key for a caller-supplied private scalar.
 */
export const generateParametersWithPrivateKey = (
    privateKey: bigint,
): ElgamalKeyPair => {
    assertValidPrivateKey(privateKey);
    const publicKey = encodePoint(multiplyBase(privateKey));

    return {
        publicKey,
        privateKey,
    };
};

/**
 * Generates a fresh ElGamal key pair for the built-in suite.
 */
export const generateParameters = (): ElgamalKeyPair =>
    generateParametersWithPrivateKey(
        randomScalarInRange(1n, RISTRETTO_GROUP.q),
    );
