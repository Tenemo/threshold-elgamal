[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / payloadSlotKey

# Function: payloadSlotKey()

> **payloadSlotKey**(`payload`): `string`

Computes the canonical slot key used for idempotence and equivocation checks.

## Parameters

### payload

[`ProtocolPayload`](../type-aliases/ProtocolPayload.md)

Unsigned protocol payload.

## Returns

`string`

Stable slot key for the payload author and phase slot.
