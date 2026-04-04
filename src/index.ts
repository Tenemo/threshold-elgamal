import { generateParameters, encrypt, decrypt } from './elgamal.js';
import {
    generateKeys,
    generateKeyShares,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
} from './thresholdElgamal.js';
import type { EncryptedMessage, Parameters } from './types.js';
import {
    getRandomBigIntegerInRange,
    multiplyEncryptedValues,
    getGroup,
    serializeEncryptedMessage,
    deserializeEncryptedMessage,
} from './utils/utils.js';

export {
    generateParameters,
    encrypt,
    decrypt,
    generateKeys,
    generateKeyShares,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
    getRandomBigIntegerInRange,
    multiplyEncryptedValues,
    getGroup,
    serializeEncryptedMessage,
    deserializeEncryptedMessage,
};
export type { EncryptedMessage, Parameters };
