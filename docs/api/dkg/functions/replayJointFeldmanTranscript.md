[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [dkg](../index.md) / replayJointFeldmanTranscript

# Function: replayJointFeldmanTranscript()

> **replayJointFeldmanTranscript**(`config`, `transcript`): [`DKGState`](../type-aliases/DKGState.md)

Replays a Joint-Feldman transcript from the initial state.

## Parameters

### config

[`DKGConfig`](../type-aliases/DKGConfig.md)

DKG configuration.

### transcript

readonly [`SignedPayload`](../../protocol/type-aliases/SignedPayload.md)[]

Signed transcript payloads.

## Returns

[`DKGState`](../type-aliases/DKGState.md)

Final Joint-Feldman state after replay.
