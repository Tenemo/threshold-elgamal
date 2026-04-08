---
title: "canonicalUnsignedPayloadBytes"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / canonicalUnsignedPayloadBytes

# Function: canonicalUnsignedPayloadBytes()

> **canonicalUnsignedPayloadBytes**(`payload`, `bigintByteLength?`): `Uint8Array`

Serializes the unsigned payload into canonical bytes.

## Parameters

### payload

[`ProtocolPayload`](../type-aliases/ProtocolPayload/)

Unsigned protocol payload.

### bigintByteLength?

`number`

Fixed byte width used for any bigint fields.

## Returns

`Uint8Array`

Canonical unsigned payload bytes.
