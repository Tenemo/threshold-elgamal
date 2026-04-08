---
title: "payloadSlotKey"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / payloadSlotKey

# Function: payloadSlotKey()

> **payloadSlotKey**(`payload`): `string`

Computes the canonical slot key used for idempotence and equivocation checks.

## Parameters

### payload

[`ProtocolPayload`](../type-aliases/ProtocolPayload/)

Unsigned protocol payload.

## Returns

`string`

Stable slot key for the payload author and message slot.
