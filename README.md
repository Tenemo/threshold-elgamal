# Threshold ElGamal

This project implements the ElGamal encryption algorithm in TypeScript. It includes functions for key generation, encryption, and decryption, along with additional support for threshold encryption.

## Setup

Ensure you have Node.js installed on your system and then install the required dependencies by running:

```
npm install
```

## Generating Parameters

To generate encryption parameters including the public and private keys, use the `generateParameters` function:

```
import { generateParameters } from './path/to/module';

const { prime, generator, publicKey, privateKey } = generateParameters(2048);
```

`primeBits` can be `2048`, `3072`, or `4096`, depending on the desired security level.

## Encrypting a Message

To encrypt a message, use the `encrypt` function with the message, prime, generator, and public key:

```
import { encrypt } from './path/to/module';

const message = 42; // The message to encrypt
const encryptedMessage = encrypt(message, prime, generator, publicKey);
```

## Decrypting a Message

To decrypt an encrypted message, use the `decrypt` function with the encrypted message, prime, generator, privateKey, and publicKey:

```
import { decrypt } from './path/to/module';

const decryptedMessage = decrypt(encryptedMessage, prime, generator, privateKey, publicKey);
console.log(decryptedMessage); // 42
```

## Threshold Encryption

This implementation also supports threshold encryption. Functions are provided to generate individual key pairs, combine public keys, perform partial decryptions, and combine partial decryptions for the final decryption step.

### Generating Individual Key Pairs

```
import { generateIndividualKeyPair } from './path/to/thresholdElgamal';

const keyPair = generateIndividualKeyPair(2048);
```

### Combining Public Keys

```
import { combinePublicKeys } from './path/to/thresholdElgamal';

const combinedPublicKey = combinePublicKeys([keyPair1.publicKey, keyPair2.publicKey], prime);
```

### Partial Decryption and Combining Decryptions

Partial decryptions are performed by each party with their private key. These partial decryptions are then combined to decrypt the message.

```
import { partialDecrypt, combinePartialDecryptions, thresholdDecrypt } from './path/to/thresholdElgamal';

const partialDecryption1 = partialDecrypt(encryptedMessage.c1, keyPair1.privateKey, prime);
const partialDecryption2 = partialDecrypt(encryptedMessage.c1, keyPair2.privateKey, prime);

const combinedDecryptions = combinePartialDecryptions([partialDecryption1, partialDecryption2], prime);
const decryptedMessage = thresholdDecrypt(encryptedMessage, combinedDecryptions, prime);
```

For more detailed examples and additional functionality, refer to the source code and tests provided in this repository.
