---
title: "BallotSubmissionPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / BallotSubmissionPayload

# Type alias: BallotSubmissionPayload

> **BallotSubmissionPayload** = [`BaseProtocolPayload`](BaseProtocolPayload/) & `object`

Signed additive ballot payload for one participant and one option slot.

## Type declaration

### ciphertext

> `readonly` **ciphertext**: [`EncodedCiphertext`](EncodedCiphertext/)

### messageType

> `readonly` **messageType**: `"ballot-submission"`

### optionIndex

> `readonly` **optionIndex**: `number`

### proof

> `readonly` **proof**: [`EncodedDisjunctiveProof`](EncodedDisjunctiveProof/)
