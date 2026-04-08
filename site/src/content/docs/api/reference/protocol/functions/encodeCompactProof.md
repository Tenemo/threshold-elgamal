---
title: "encodeCompactProof"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / encodeCompactProof

# Function: encodeCompactProof()

> **encodeCompactProof**(`proof`, `byteLength`): [`EncodedCompactProof`](../type-aliases/EncodedCompactProof/)

Encodes a compact challenge-response proof into fixed-width protocol hex.

## Parameters

### proof

Compact proof to encode.

#### challenge

`bigint`

#### response

`bigint`

### byteLength

`number`

Fixed group byte width.

## Returns

[`EncodedCompactProof`](../type-aliases/EncodedCompactProof/)

Protocol proof encoding.
