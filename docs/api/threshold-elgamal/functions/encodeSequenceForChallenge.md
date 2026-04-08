[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / encodeSequenceForChallenge

# Function: encodeSequenceForChallenge()

> **encodeSequenceForChallenge**(`elements`): `Uint8Array`

Injectively encodes a variable-length sequence for challenge transcripts.

The output starts with a 4-byte big-endian element count followed by the
standard length-prefixed encoding for each element.

## Parameters

### elements

readonly (`string` \| `bigint` \| `Uint8Array`\<`ArrayBufferLike`\>)[]

Sequence elements to encode in order.

## Returns

`Uint8Array`

A deterministic count-prefixed byte encoding of `elements`.

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError.md) When a bigint element is negative.

## Throws

[InvalidPayloadError](../../core/classes/InvalidPayloadError.md) When an encoded element length is invalid.
