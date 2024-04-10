import { generateParameters, encrypt, decrypt } from './elgamal';
import {
    generateKeys,
    generateKeyShares,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
} from './thresholdElgamal';
import type { EncryptedMessage, Parameters } from './types';
import {
    getRandomBigIntegerInRange,
    multiplyEncryptedValues,
    getGroup,
    serializeEncryptedMessage,
    deserializeEncryptedMessage,
} from './utils/utils';

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
