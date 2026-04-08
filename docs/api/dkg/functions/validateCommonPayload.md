[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [dkg](../index.md) / validateCommonPayload

# Function: validateCommonPayload()

> **validateCommonPayload**(`state`, `signedPayload`): [`DKGError`](../type-aliases/DKGError.md) \| `null`

Validates session-level fields shared by every DKG payload.

## Parameters

### state

[`DKGState`](../type-aliases/DKGState.md)

Current reducer state.

### signedPayload

[`SignedPayload`](../../protocol/type-aliases/SignedPayload.md)

Incoming signed payload.

## Returns

[`DKGError`](../type-aliases/DKGError.md) \| `null`

Structured validation error, or `null` when the payload matches.
