---
title: "SignedPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / SignedPayload

# Type alias: SignedPayload\<TPayload\>

> **SignedPayload**\<`TPayload`\> = `object`

Unsigned protocol payload paired with an authentication signature.

## Type parameters

### TPayload

`TPayload` *extends* [`ProtocolPayload`](ProtocolPayload/) = [`ProtocolPayload`](ProtocolPayload/)

## Properties

### payload

> `readonly` **payload**: `TPayload`

***

### signature

> `readonly` **signature**: `string`

Raw IEEE P1363 signature bytes encoded as lowercase hex.
