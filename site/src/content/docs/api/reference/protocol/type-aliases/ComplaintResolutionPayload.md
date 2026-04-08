---
title: "ComplaintResolutionPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / ComplaintResolutionPayload

# Type alias: ComplaintResolutionPayload

> **ComplaintResolutionPayload** = [`BaseProtocolPayload`](BaseProtocolPayload/) & `object`

Dealer-signed complaint-resolution payload carrying the sender-ephemeral
private key that lets every verifier independently resolve one complaint.

## Type declaration

### complainantIndex

> `readonly` **complainantIndex**: `number`

### dealerIndex

> `readonly` **dealerIndex**: `number`

### envelopeId

> `readonly` **envelopeId**: `string`

### messageType

> `readonly` **messageType**: `"complaint-resolution"`

### revealedEphemeralPrivateKey

> `readonly` **revealedEphemeralPrivateKey**: `string`

### suite

> `readonly` **suite**: `"X25519"` \| `"P-256"`
