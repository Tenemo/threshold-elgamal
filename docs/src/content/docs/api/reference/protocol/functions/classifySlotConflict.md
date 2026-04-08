---
title: "classifySlotConflict"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / classifySlotConflict

# Function: classifySlotConflict()

> **classifySlotConflict**(`left`, `right`, `bigintByteLength?`): `"distinct"` \| `"idempotent"` \| `"equivocation"`

Classifies how two signed payloads for the same slot relate to one another.

Payloads with identical unsigned canonical bytes are idempotent
retransmissions even when the signatures differ.

## Parameters

### left

[`SignedPayload`](../type-aliases/SignedPayload/)

First signed payload.

### right

[`SignedPayload`](../type-aliases/SignedPayload/)

Second signed payload.

### bigintByteLength?

`number`

Fixed byte width used for any bigint fields.

## Returns

`"distinct"` \| `"idempotent"` \| `"equivocation"`

`distinct`, `idempotent`, or `equivocation`.
