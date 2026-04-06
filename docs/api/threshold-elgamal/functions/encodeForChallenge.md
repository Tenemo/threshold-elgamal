[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / encodeForChallenge

# Function: encodeForChallenge()

> **encodeForChallenge**(...`elements`): `Uint8Array`

Injectively encodes challenge transcript elements with 4-byte big-endian
length prefixes.

This helper is intended for Fiat-Shamir style transcripts where different
element sequences must never collide after encoding.

## Parameters

### elements

...(`string` \| `bigint` \| `Uint8Array`\<`ArrayBufferLike`\>)[]

## Returns

`Uint8Array`

## Example

```ts
const payload = encodeForChallenge('dleq', 7n, new Uint8Array([1, 2, 3]));
```

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When a bigint element is negative.

## Throws

[InvalidPayloadError](../classes/InvalidPayloadError.md) When an encoded element length is invalid.
