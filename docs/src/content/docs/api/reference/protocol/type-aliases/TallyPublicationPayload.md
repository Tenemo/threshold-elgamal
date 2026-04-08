---
title: "TallyPublicationPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / TallyPublicationPayload

# Type alias: TallyPublicationPayload

> **TallyPublicationPayload** = [`BaseProtocolPayload`](BaseProtocolPayload/) & `object`

Signed tally-publication payload for the recovered additive tally.

## Type declaration

### ballotCount

> `readonly` **ballotCount**: `number`

### decryptionParticipantIndices

> `readonly` **decryptionParticipantIndices**: readonly `number`[]

### messageType

> `readonly` **messageType**: `"tally-publication"`

### tally

> `readonly` **tally**: `string`

### transcriptHash

> `readonly` **transcriptHash**: `string`
