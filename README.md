# Threshold ElGamal

[![npm version](https://badge.fury.io/js/threshold-elgamal.svg)](https://badge.fury.io/js/threshold-elgamal)

This project is a collection of functions implementing selected ElGamal cryptographic algorithms in TypeScript on top of native JavaScript BigInteger. Its core includes ElGamal functions for key generation, encryption, and decryption. It is extended with support for threshold encryption. Runs both in Node and in browsers.

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

It has no other production dependencies apart from this one. It could be inlined easily, if needed.

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
import { generateParameters, encrypt, decrypt } from "threshold-elgamal";
```

### Generating keys, encrypting and decrypting a secret

```typescript
// Generate a public/private key pair
// If prime and generator aren't specified, they default to the 2048-bit group.
const { publicKey, privateKey, prime, generator } = generateParameters();

// Encrypt a message using the public key:
const secret = 859;
const encryptedMessage = encrypt(secret, publicKey, prime, generator);

// Decrypt the message using the private key:
const decryptedMessage = decrypt(encryptedMessage, prime, privateKey);
// console.log(decryptedMessage); // 859
```

### Single secret shared with 3 participants

Threshold scheme for generating a common public key, sharing a secret to 3 participants using that key and requiring all three participants to decrypt it.

```typescript
import {
    encrypt,
    generateKeys,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
} from "threshold-elgamal";

const threshold = 3; // A scenario for 3 participants with a threshold of 3

// Each participant generates their public key share and private key individually
const participant1Keys = generateKeys(1, threshold);
const participant2Keys = generateKeys(2, threshold);
const participant3Keys = generateKeys(3, threshold);

// Combine the public keys to form a single public key
const commonPublicKey = combinePublicKeys([
    participant1Keys.publicKey,
    participant2Keys.publicKey,
    participant3Keys.publicKey,
]);

// Encrypt a message using the combined public key
const secret = 42;
const encryptedMessage = encrypt(secret, commonPublicKey);

// Decryption shares
const decryptionShares = [
    createDecryptionShare(encryptedMessage, participant1Keys.privateKey),
    createDecryptionShare(encryptedMessage, participant2Keys.privateKey),
    createDecryptionShare(encryptedMessage, participant3Keys.privateKey),
];
// Combining the decryption shares into one, used to decrypt the message
const combinedDecryptionShares = combineDecryptionShares(decryptionShares);

// Decrypting the message using the combined decryption shares
const thresholdDecryptedMessage = thresholdDecrypt(
    encryptedMessage,
    combinedDecryptionShares,
);
console.log(thresholdDecryptedMessage); // 42
```

### Voting and multiplication with threshold scheme for 3 participants

This example demonstrates a 1 to 10 voting scenario where 3 participants cast encrypted votes on two options. The encrypted votes are aggregated, multiplied with each other and then require all three participants to decrypt the final tally. The decryption does not work on individual votes, meaning that it is impossible to decrypt their votes even after decrypting the result.

```typescript
import {
    encrypt,
    generateKeys,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
    multiplyEncryptedValues,
} from "threshold-elgamal";

const threshold = 3; // A scenario for 3 participants with a threshold of 3

// Each participant generates their public key share and private key individually
const participant1Keys = generateKeys(1, threshold);
const participant2Keys = generateKeys(2, threshold);
const participant3Keys = generateKeys(3, threshold);

// Combine the public keys to form a single public key
const commonPublicKey = combinePublicKeys([
    participant1Keys.publicKey,
    participant2Keys.publicKey,
    participant3Keys.publicKey,
]);

// Participants cast their encrypted votes for two options
const voteOption1 = [6, 7, 1]; // Votes for option 1 by participants 1, 2, and 3
const voteOption2 = [10, 7, 4]; // Votes for option 2 by participants 1, 2, and 3

// Encrypt votes for both options
const encryptedVotesOption1 = voteOption1.map((vote) =>
    encrypt(vote, commonPublicKey),
);
const encryptedVotesOption2 = voteOption2.map((vote) =>
    encrypt(vote, commonPublicKey),
);

// Multiply encrypted votes together to aggregate
const aggregatedEncryptedVoteOption1 = encryptedVotesOption1.reduce(
    (talliedVotes, encryptedVote) =>
        multiplyEncryptedValues(talliedVotes, encryptedVote),
    { c1: 1n, c2: 1n },
);
const aggregatedEncryptedVoteOption2 = encryptedVotesOption2.reduce(
    (talliedVotes, encryptedVote) =>
        multiplyEncryptedValues(talliedVotes, encryptedVote),
    { c1: 1n, c2: 1n },
);

// Each participant creates a decryption share for both options.
// Notice that the shares are created for the aggregated, multiplied tally specifically,
// not the individual votes. This means that they can be used ONLY for decrypting the aggregated votes.
const decryptionSharesOption1 = [
    createDecryptionShare(
        aggregatedEncryptedVoteOption1,
        // The order of the shares does not matter during decryption.
        participant3Keys.privateKey,
    ),
    createDecryptionShare(
        aggregatedEncryptedVoteOption1,
        participant1Keys.privateKey,
    ),
    createDecryptionShare(
        aggregatedEncryptedVoteOption1,
        participant2Keys.privateKey,
    ),
];
const decryptionSharesOption2 = [
    createDecryptionShare(
        aggregatedEncryptedVoteOption2,
        participant2Keys.privateKey,
    ),
    createDecryptionShare(
        aggregatedEncryptedVoteOption2,
        participant1Keys.privateKey,
    ),
    createDecryptionShare(
        aggregatedEncryptedVoteOption2,
        participant3Keys.privateKey,
    ),
];

// Combine decryption shares and decrypt the aggregated votes for both options.
// Notice that the private keys of the participants never leave their possession.
// Only the decryption shares are shared with other participants.
const combinedDecryptionSharesOption1 = combineDecryptionShares(
    decryptionSharesOption1,
);
const combinedDecryptionSharesOption2 = combineDecryptionShares(
    decryptionSharesOption2,
);

const finalTallyOption1 = thresholdDecrypt(
    aggregatedEncryptedVoteOption1,
    combinedDecryptionSharesOption1,
);
const finalTallyOption2 = thresholdDecrypt(
    aggregatedEncryptedVoteOption2,
    combinedDecryptionSharesOption2,
);

console.log(
    `Final tally for Option 1: ${finalTallyOption1}, Option 2: ${finalTallyOption2}`,
); // 42, 280
```

This example can be extended with calculating a geometric mean for the candidate options to better present the results.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
