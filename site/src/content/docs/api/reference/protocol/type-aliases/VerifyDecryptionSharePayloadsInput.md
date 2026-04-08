---
title: "VerifyDecryptionSharePayloadsInput"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / VerifyDecryptionSharePayloadsInput

# Type alias: VerifyDecryptionSharePayloadsInput

> **VerifyDecryptionSharePayloadsInput** = `object`

Input bundle for verifying typed decryption-share payloads.

## Properties

### aggregate

> `readonly` **aggregate**: [`VerifiedBallotAggregation`](VerifiedBallotAggregation/)\[`"aggregate"`\]

***

### decryptionSharePayloads

> `readonly` **decryptionSharePayloads**: readonly [`SignedPayload`](SignedPayload/)\<[`DecryptionSharePayload`](DecryptionSharePayload/)\>[]

***

### dkg

> `readonly` **dkg**: [`VerifiedDKGTranscript`](../../dkg/type-aliases/VerifiedDKGTranscript/)

***

### manifest

> `readonly` **manifest**: [`ElectionManifest`](ElectionManifest/)

***

### sessionId

> `readonly` **sessionId**: `string`
