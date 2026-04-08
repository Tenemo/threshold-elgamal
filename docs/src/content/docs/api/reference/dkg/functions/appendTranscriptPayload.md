---
title: "appendTranscriptPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / appendTranscriptPayload

# Function: appendTranscriptPayload()

> **appendTranscriptPayload**(`state`, `signedPayload`): [`DKGTransition`](../type-aliases/DKGTransition/)

Appends one payload to the transcript while enforcing slot idempotence and
equivocation detection.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState/)

Current reducer state.

### signedPayload

[`SignedPayload`](../../protocol/type-aliases/SignedPayload/)

Incoming signed payload.

## Returns

[`DKGTransition`](../type-aliases/DKGTransition/)

Transition with either an updated transcript or an abort.
