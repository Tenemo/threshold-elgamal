import { generateParameters, encrypt, decrypt } from './elgamal';
import {
    generateSingleKeyShare,
    generateKeyShares,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
} from './thresholdElgamal';
import type {
    EncryptedMessage,
    Parameters,
    KeyPair,
    PartyKeyPair,
} from './types';
import {
    getRandomBigIntegerInRange,
    multiplyEncryptedValues,
    getGroup,
} from './utils';

export {
    generateParameters,
    encrypt,
    decrypt,
    generateSingleKeyShare,
    generateKeyShares,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
    getRandomBigIntegerInRange,
    multiplyEncryptedValues,
    getGroup,
};
export type { EncryptedMessage, Parameters, KeyPair, PartyKeyPair };
