[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / ManifestAcceptancePayload

# Type alias: ManifestAcceptancePayload

> **ManifestAcceptancePayload** = [`BaseProtocolPayload`](BaseProtocolPayload.md) & `object`

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
