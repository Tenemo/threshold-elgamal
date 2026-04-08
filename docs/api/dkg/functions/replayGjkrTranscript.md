[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [dkg](../index.md) / replayGjkrTranscript

# Function: replayGjkrTranscript()

> **replayGjkrTranscript**(`config`, `transcript`): [`DKGState`](../type-aliases/DKGState.md)

Replays a GJKR transcript from the initial state.

## Parameters

### config

[`DKGConfig`](../type-aliases/DKGConfig.md)

DKG configuration.

### transcript

readonly [`SignedPayload`](../../protocol/type-aliases/SignedPayload.md)[]

Signed transcript payloads.

## Returns

[`DKGState`](../type-aliases/DKGState.md)

Final GJKR state after replay.
