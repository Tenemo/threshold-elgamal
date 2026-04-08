[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [dkg](../index.md) / processGjkrPayload

# Function: processGjkrPayload()

> **processGjkrPayload**(`state`, `signedPayload`): [`DKGTransition`](../type-aliases/DKGTransition.md)

Processes one signed payload through the GJKR log reducer.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState.md)

Current GJKR state.

### signedPayload

[`SignedPayload`](../../protocol/type-aliases/SignedPayload.md)

Incoming signed payload.

## Returns

[`DKGTransition`](../type-aliases/DKGTransition.md)

Deterministic state transition result.
