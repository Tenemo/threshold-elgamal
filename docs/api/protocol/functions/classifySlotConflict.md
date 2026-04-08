[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / classifySlotConflict

# Function: classifySlotConflict()

> **classifySlotConflict**(`left`, `right`, `bigintByteLength?`): `"distinct"` \| `"idempotent"` \| `"equivocation"`

Classifies how two signed payloads for the same slot relate to one another.

Payloads with identical unsigned canonical bytes are idempotent
retransmissions even when the signatures differ.

## Parameters

### left

[`SignedPayload`](../type-aliases/SignedPayload.md)

First signed payload.

### right

[`SignedPayload`](../type-aliases/SignedPayload.md)

Second signed payload.

### bigintByteLength?

`number`

Fixed byte width used for any bigint fields.

## Returns

`"distinct"` \| `"idempotent"` \| `"equivocation"`

`distinct`, `idempotent`, or `equivocation`.
