[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / canonicalUnsignedPayloadBytes

# Function: canonicalUnsignedPayloadBytes()

> **canonicalUnsignedPayloadBytes**(`payload`, `bigintByteLength?`): `Uint8Array`

Serializes the unsigned payload into canonical bytes.

## Parameters

### payload

[`ProtocolPayload`](../type-aliases/ProtocolPayload.md)

Unsigned protocol payload.

### bigintByteLength?

`number`

Fixed byte width used for any bigint fields.

## Returns

`Uint8Array`

Canonical unsigned payload bytes.
