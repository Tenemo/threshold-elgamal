[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / SignedPayload

# Type alias: SignedPayload\<TPayload\>

> **SignedPayload**\<`TPayload`\> = `object`

Unsigned protocol payload paired with an authentication signature.

## Type parameters

### TPayload

`TPayload` *extends* [`ProtocolPayload`](ProtocolPayload.md) = [`ProtocolPayload`](ProtocolPayload.md)

## Properties

### payload

> `readonly` **payload**: `TPayload`

***

### signature

> `readonly` **signature**: `string`

Raw IEEE P1363 signature bytes encoded as lowercase hex.
