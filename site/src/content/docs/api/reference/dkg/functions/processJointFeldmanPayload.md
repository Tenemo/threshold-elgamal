---
title: "processJointFeldmanPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / processJointFeldmanPayload

# Function: processJointFeldmanPayload()

> **processJointFeldmanPayload**(`state`, `signedPayload`): [`DKGTransition`](../type-aliases/DKGTransition/)

Processes one signed payload through the Joint-Feldman log reducer.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState/)

Current Joint-Feldman state.

### signedPayload

[`SignedPayload`](../../protocol/type-aliases/SignedPayload/)

Incoming signed payload.

## Returns

[`DKGTransition`](../type-aliases/DKGTransition/)

Deterministic state transition result.
