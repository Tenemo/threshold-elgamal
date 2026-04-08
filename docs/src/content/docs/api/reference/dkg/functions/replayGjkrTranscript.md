---
title: "replayGjkrTranscript"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / replayGjkrTranscript

# Function: replayGjkrTranscript()

> **replayGjkrTranscript**(`config`, `transcript`): [`DKGState`](../type-aliases/DKGState/)

Replays a GJKR transcript from the initial state.

## Parameters

### config

[`MajorityDKGConfigInput`](../type-aliases/MajorityDKGConfigInput/)

DKG configuration.

### transcript

readonly [`SignedPayload`](../../protocol/type-aliases/SignedPayload/)[]

Signed transcript payloads.

## Returns

[`DKGState`](../type-aliases/DKGState/)

Final GJKR state after replay.
