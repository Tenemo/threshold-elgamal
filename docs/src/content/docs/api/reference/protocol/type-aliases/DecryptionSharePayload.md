---
title: "DecryptionSharePayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / DecryptionSharePayload

# Type alias: DecryptionSharePayload

> **DecryptionSharePayload** = [`BaseProtocolPayload`](BaseProtocolPayload/) & `object`

Signed threshold decryption-share payload tied to a locally recomputed
additive aggregate transcript.

## Type declaration

### ballotCount

> `readonly` **ballotCount**: `number`

### decryptionShare

> `readonly` **decryptionShare**: `string`

### messageType

> `readonly` **messageType**: `"decryption-share"`

### proof

> `readonly` **proof**: [`EncodedCompactProof`](EncodedCompactProof/)

### transcriptHash

> `readonly` **transcriptHash**: `string`
