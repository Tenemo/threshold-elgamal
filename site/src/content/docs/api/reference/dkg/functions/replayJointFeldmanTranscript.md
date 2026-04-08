---
title: "replayJointFeldmanTranscript"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / replayJointFeldmanTranscript

# Function: replayJointFeldmanTranscript()

> **replayJointFeldmanTranscript**(`config`, `transcript`): [`DKGState`](../type-aliases/DKGState/)

Replays a Joint-Feldman transcript from the initial state.

## Parameters

### config

[`MajorityDKGConfigInput`](../type-aliases/MajorityDKGConfigInput/)

DKG configuration.

### transcript

readonly [`SignedPayload`](../../protocol/type-aliases/SignedPayload/)[]

Signed transcript payloads.

## Returns

[`DKGState`](../type-aliases/DKGState/)

Final Joint-Feldman state after replay.
