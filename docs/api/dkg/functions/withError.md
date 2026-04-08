[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [dkg](../index.md) / withError

# Function: withError()

> **withError**(`state`, `code`, `message`): [`DKGTransition`](../type-aliases/DKGTransition.md)

Builds a no-op transition carrying one structured reducer error.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState.md)

Current reducer state.

### code

`string`

Stable error code.

### message

`string`

Human-readable error message.

## Returns

[`DKGTransition`](../type-aliases/DKGTransition.md)

Transition preserving `state` and reporting one error.
