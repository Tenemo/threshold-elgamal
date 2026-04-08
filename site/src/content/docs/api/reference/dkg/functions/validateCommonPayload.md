---
title: "validateCommonPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / validateCommonPayload

# Function: validateCommonPayload()

> **validateCommonPayload**(`state`, `signedPayload`): [`DKGError`](../type-aliases/DKGError/) \| `null`

Validates session-level fields shared by every DKG payload.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState/)

Current reducer state.

### signedPayload

[`SignedPayload`](../../protocol/type-aliases/SignedPayload/)

Incoming signed payload.

## Returns

[`DKGError`](../type-aliases/DKGError/) \| `null`

Structured validation error, or `null` when the payload matches.
