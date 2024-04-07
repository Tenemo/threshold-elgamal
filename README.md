# Threshold ElGamal

**WIP: Early version. Thresholds when set below the number of scheme participants don't behave as expected.**
It, however, works correctly with `threshold == participantsCount`, which is its main use case for myself.

This project implements the ElGamal encryption algorithm in TypeScript. Its core includes ElGamal functions for key generation, encryption, and decryption. It is extended with support for threshold encryption.

It was written as clearly as possible, modularized and with long, explicit variable names.

## TODO

-   Hashing messages
-   Support for additive property of exponents, not just native ElGamal multiplication

## Contributing

The JavaScript/TypeScript ecosystem seems to be lacking in modern, functional ElGamal libraries that work out of the box with reasonable default (this library isn't at that point yet). All PRs are welcome.

## Setup

Ensure you have Node.js installed on your system and then install the required dependencies by running:

```
npm install
```
