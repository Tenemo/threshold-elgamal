export { generateParameters, encrypt, decrypt } from './elgamal';

export {
    generateSingleKeyShare,
    generateKeyShares,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
} from './thresholdElgamal';

export { getRandomBigIntegerInRange, multiplyEncryptedValues } from './utils';

export type {
    EncryptedMessage,
    Parameters,
    KeyPair,
    PartyKeyPair,
} from './types';
