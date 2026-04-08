---
title: "encodeForChallenge"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / encodeForChallenge

# Function: encodeForChallenge()

> **encodeForChallenge**(...`elements`): `Uint8Array`

Injectively encodes challenge transcript elements with 4-byte big-endian
length prefixes.

This helper is intended for Fiat-Shamir style transcripts where different
element sequences must never collide after encoding.

## Parameters

### elements

...(`string` \| `bigint` \| `Uint8Array`\<`ArrayBufferLike`\>)[]

Transcript elements to encode in order.

## Returns

`Uint8Array`

A deterministic length-prefixed byte encoding of `elements`.

## Example

```ts
const payload = encodeForChallenge('dleq', 7n, new Uint8Array([1, 2, 3]));
```

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError/) When a bigint element is negative.

## Throws

[InvalidPayloadError](../../core/classes/InvalidPayloadError/) When an encoded element length is invalid.
