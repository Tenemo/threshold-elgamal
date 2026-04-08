[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [dkg](../index.md) / appendTranscriptPayload

# Function: appendTranscriptPayload()

> **appendTranscriptPayload**(`state`, `signedPayload`): [`DKGTransition`](../type-aliases/DKGTransition.md)

Appends one payload to the transcript while enforcing slot idempotence and
equivocation detection.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState.md)

Current reducer state.

### signedPayload

[`SignedPayload`](../../protocol/type-aliases/SignedPayload.md)

Incoming signed payload.

## Returns

[`DKGTransition`](../type-aliases/DKGTransition.md)

Transition with either an updated transcript or an abort.
