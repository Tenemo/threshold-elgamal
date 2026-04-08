[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [dkg](../index.md) / processJointFeldmanPayload

# Function: processJointFeldmanPayload()

> **processJointFeldmanPayload**(`state`, `signedPayload`): [`DKGTransition`](../type-aliases/DKGTransition.md)

Processes one signed payload through the Joint-Feldman log reducer.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState.md)

Current Joint-Feldman state.

### signedPayload

[`SignedPayload`](../../protocol/type-aliases/SignedPayload.md)

Incoming signed payload.

## Returns

[`DKGTransition`](../type-aliases/DKGTransition.md)

Deterministic state transition result.
