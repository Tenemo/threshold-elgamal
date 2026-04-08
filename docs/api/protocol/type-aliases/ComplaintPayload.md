[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / ComplaintPayload

# Type alias: ComplaintPayload

> **ComplaintPayload** = [`BaseProtocolPayload`](BaseProtocolPayload.md) & `object`

Complaint payload against a dealer envelope or share.

## Type declaration

### dealerIndex

> `readonly` **dealerIndex**: `number`

### envelopeId

> `readonly` **envelopeId**: `string`

### messageType

> `readonly` **messageType**: `"complaint"`

### reason

> `readonly` **reason**: [`ComplaintReason`](ComplaintReason.md)
