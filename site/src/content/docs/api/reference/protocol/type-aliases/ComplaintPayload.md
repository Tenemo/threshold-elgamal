---
title: "ComplaintPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / ComplaintPayload

# Type alias: ComplaintPayload

> **ComplaintPayload** = [`BaseProtocolPayload`](BaseProtocolPayload/) & `object`

Complaint payload against a dealer envelope or share.

## Type declaration

### dealerIndex

> `readonly` **dealerIndex**: `number`

### envelopeId

> `readonly` **envelopeId**: `string`

### messageType

> `readonly` **messageType**: `"complaint"`

### reason

> `readonly` **reason**: [`ComplaintReason`](ComplaintReason/)
