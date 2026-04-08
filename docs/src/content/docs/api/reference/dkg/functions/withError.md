---
title: "withError"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / withError

# Function: withError()

> **withError**(`state`, `code`, `message`): [`DKGTransition`](../type-aliases/DKGTransition/)

Builds a no-op transition carrying one structured reducer error.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState/)

Current reducer state.

### code

`string`

Stable error code.

### message

`string`

Human-readable error message.

## Returns

[`DKGTransition`](../type-aliases/DKGTransition/)

Transition preserving `state` and reporting one error.
