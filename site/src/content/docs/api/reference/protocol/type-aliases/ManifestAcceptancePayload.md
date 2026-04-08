---
title: "ManifestAcceptancePayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / ManifestAcceptancePayload

# Type alias: ManifestAcceptancePayload

> **ManifestAcceptancePayload** = [`BaseProtocolPayload`](BaseProtocolPayload/) & `object`

Participant-signed manifest acceptance payload.

## Type declaration

### accountIdHash?

> `readonly` `optional` **accountIdHash?**: `string`

### assignedParticipantIndex

> `readonly` **assignedParticipantIndex**: `number`

### messageType

> `readonly` **messageType**: `"manifest-acceptance"`

### rosterHash

> `readonly` **rosterHash**: `string`
