# Threshold ElGamal

[![npm version](https://badge.fury.io/js/threshold-elgamal.svg)](https://badge.fury.io/js/threshold-elgamal)

This project is a collection of functions implementing selected ElGamal cryptographic algorithms in TypeScript on top of native JavaScript BigInteger. Its core includes ElGamal functions for key generation, encryption, and decryption. It is extended with support for threshold encryption.

**WIP: Early version. Thresholds when set below the number of scheme participants don't behave as expected.**
However, it works correctly with `threshold == participantsCount`, which is its main use case for myself for now.

It was written as clearly as possible, modularized, and with long, explicit variable names. It includes out-of-the-box VS Code configuration, including recommended extensions for working with the library and/or contributing.

**This is not a cryptographically audited library, make sure you know what you are doing before using it.**

## Documentation

For a detailed list of exported types and functions, [click here](https://tenemo.github.io/threshold-elgamal/modules.html).

## Contributing

The JavaScript/TypeScript ecosystem seems to be lacking in modern, functional ElGamal libraries that work out of the box with reasonable default (this library isn't at that point yet). All PRs are welcome.

## Libraries/tools used

-   TypeScript
-   Vitest
-   ESLint + Prettier
-   Typedoc

## Production dependencies

-   [bigint-mod-arith](https://www.npmjs.com/package/bigint-mod-arith)
-   [random-bigint](https://www.npmjs.com/package/random-bigint)

It has no other production dependencies apart from these two. They could be inlined easily, if needed.

## TODO

-   Hashing messages
-   Support for additive property of exponents, not just native ElGamal multiplication
-   consider using {} function params for better readability and consistency in param naming
-   ZK proofs
-   Validation

## Installation

To use it in your project, install it first:

`npm install --save threshold-elgamal`

## Examples

First, import the whatever functions you need from the library:

```typescript
import {
    generateParameters,
    encrypt,
    decrypt,
    generateKeyShares,
    combinePublicKeys,
    thresholdDecrypt,
} from "threshold-elgamal";
```

### Generating Keys

Generate a public/private key pair:

```typescript
const { publicKey, privateKey, prime, generator } = generateParameters();
console.log(publicKey, privateKey, prime, generator); // ffdhe2048 group by default
```

### Encrypting a Message

Encrypt a message using the public key:

```typescript
const secret = 42;
const encryptedMessage = encrypt(secret, prime, generator, publicKey);
console.log(encryptedMessage);
```

### Decrypting a Message

Decrypt a message using the private key:

```typescript
const decryptedMessage = decrypt(encryptedMessage, prime, privateKey);
console.log(decryptedMessage); // 42
```

### Single secret shared with 3 participants

Threshold scheme for generating a common public key, sharing a secret to 3 participants using that key and requiring all three participants to decrypt it.

```typescript
import {
    getGroup,
    encrypt,
    generateSingleKeyShare,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
} from "threshold-elgamal";

const primeBits = 2048; // Bit length of the prime modulus
const threshold = 3; // A scenario for 3 participants with a threshold of 3
const { prime, generator } = getGroup(2048);

// Each participant generates their public key share and private key individually
const participant1KeyShare: PartyKeyPair = generateSingleKeyShare(
    1,
    threshold,
    primeBits,
);
const participant2KeyShare: PartyKeyPair = generateSingleKeyShare(
    2,
    threshold,
    primeBits,
);
const participant3KeyShare: PartyKeyPair = generateSingleKeyShare(
    3,
    threshold,
    primeBits,
);

// Combine the public keys to form a single public key
const combinedPublicKey = combinePublicKeys(
    [
        participant1KeyShare.partyPublicKey,
        participant2KeyShare.partyPublicKey,
        participant3KeyShare.partyPublicKey,
    ],
    prime,
);

// Encrypt a message using the combined public key
const secret = 42;
const encryptedMessage = encrypt(secret, prime, generator, combinedPublicKey);

// Decryption shares
const decryptionShares = [
    createDecryptionShare(
        encryptedMessage,
        participant1KeyShare.partyPrivateKey,
        prime,
    ),
    createDecryptionShare(
        encryptedMessage,
        participant2KeyShare.partyPrivateKey,
        prime,
    ),
    createDecryptionShare(
        encryptedMessage,
        participant3KeyShare.partyPrivateKey,
        prime,
    ),
];
// Combining the decryption shares into one, used to decrypt the message
const combinedDecryptionShares = combineDecryptionShares(
    decryptionShares,
    prime,
);

// Decrypting the message using the combined decryption shares
const thresholdDecryptedMessage = thresholdDecrypt(
    encryptedMessage,
    combinedDecryptionShares,
    prime,
);
console.log(thresholdDecryptedMessage); // 42
```

### Voting and multiplication with threshold scheme for 3 participants

This example demonstrates a 1 to 10 voting scenario where 3 participants cast encrypted votes on two options. The encrypted votes are aggregated, multiplied with each other and then require all three participants to decrypt the final tally. The decryption does not work on individual votes, meaning that it is impossible to decrypt their votes even after decrypting the result.

```typescript
import {
    encrypt,
    generateSingleKeyShare,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
    multiplyEncryptedValues,
    generateParameters,
} from "threshold-elgamal";

const primeBits = 2048; // Bit length of the prime modulus
const threshold = 3; // A scenario for 3 participants with a threshold of 3
const { prime, generator } = getGroup(2048);

// Each participant generates their public key share and private key individually
const participant1KeyShare = generateSingleKeyShare(1, threshold, primeBits);
const participant2KeyShare = generateSingleKeyShare(2, threshold, primeBits);
const participant3KeyShare = generateSingleKeyShare(3, threshold, primeBits);

// Combine the public keys to form a single public key
const combinedPublicKey = combinePublicKeys(
    [
        participant1KeyShare.partyPublicKey,
        participant2KeyShare.partyPublicKey,
        participant3KeyShare.partyPublicKey,
    ],
    prime,
);

// Participants cast their encrypted votes for two options
const voteOption1 = [6, 7, 1]; // Votes for option 1 by participants 1, 2, and 3
const voteOption2 = [10, 7, 4]; // Votes for option 2 by participants 1, 2, and 3

// Encrypt votes for both options
const encryptedVotesOption1 = voteOption1.map((vote) =>
    encrypt(vote, prime, generator, combinedPublicKey),
);
const encryptedVotesOption2 = voteOption2.map((vote) =>
    encrypt(vote, prime, generator, combinedPublicKey),
);

// Multiply encrypted votes together to aggregate
const aggregatedEncryptedVoteOption1 = encryptedVotesOption1.reduce(
    (acc, current) => multiplyEncryptedValues(acc, current, prime),
    { c1: 1n, c2: 1n },
);
const aggregatedEncryptedVoteOption2 = encryptedVotesOption2.reduce(
    (acc, current) => multiplyEncryptedValues(acc, current, prime),
    { c1: 1n, c2: 1n },
);

// Each participant creates a decryption share for both options.
// Notice that the shares are created for the aggregated, multiplied tally specifically,
// not the individual votes. This means that they can be used ONLY for decrypting the aggregated votes.
const decryptionSharesOption1 = [
    createDecryptionShare(
        aggregatedEncryptedVoteOption1,
        participant1KeyShare.partyPrivateKey,
        prime,
    ),
    createDecryptionShare(
        aggregatedEncryptedVoteOption1,
        participant2KeyShare.partyPrivateKey,
        prime,
    ),
    createDecryptionShare(
        aggregatedEncryptedVoteOption1,
        participant3KeyShare.partyPrivateKey,
        prime,
    ),
];
const decryptionSharesOption2 = [
    createDecryptionShare(
        aggregatedEncryptedVoteOption2,
        participant1KeyShare.partyPrivateKey,
        prime,
    ),
    createDecryptionShare(
        aggregatedEncryptedVoteOption2,
        participant2KeyShare.partyPrivateKey,
        prime,
    ),
    createDecryptionShare(
        aggregatedEncryptedVoteOption2,
        participant3KeyShare.partyPrivateKey,
        prime,
    ),
];

// Combine decryption shares and decrypt the aggregated votes for both options.
// Notice that the private keys of the participants never leave their possession.
// Only the decryption shares are shared with other participants.
const combinedDecryptionSharesOption1 = combineDecryptionShares(
    decryptionSharesOption1,
    prime,
);
const combinedDecryptionSharesOption2 = combineDecryptionShares(
    decryptionSharesOption2,
    prime,
);

const finalTallyOption1 = thresholdDecrypt(
    aggregatedEncryptedVoteOption1,
    combinedDecryptionSharesOption1,
    prime,
);
const finalTallyOption2 = thresholdDecrypt(
    aggregatedEncryptedVoteOption2,
    combinedDecryptionSharesOption2,
    prime,
);

console.log(
    `Final tally for Option 1: ${finalTallyOption1}, Option 2: ${finalTallyOption2}`,
); // 42, 280
```

This example can be extended with calculating a geometric mean for the candidate options to better present the results.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
