---
title: "processGjkrPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / processGjkrPayload

# Function: processGjkrPayload()

> **processGjkrPayload**(`state`, `signedPayload`): [`DKGTransition`](../type-aliases/DKGTransition/)

Processes one signed payload through the GJKR log reducer.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState/)

Current GJKR state.

### signedPayload

[`SignedPayload`](../../protocol/type-aliases/SignedPayload/)

Incoming signed payload.

## Returns

[`DKGTransition`](../type-aliases/DKGTransition/)

Deterministic state transition result.
