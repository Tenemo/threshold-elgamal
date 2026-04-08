---
title: "bigintToFixedBytes"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / bigintToFixedBytes

# Function: bigintToFixedBytes()

> **bigintToFixedBytes**(`value`, `byteLength`): `Uint8Array`

Encodes a non-negative bigint as fixed-width big-endian bytes.

## Parameters

### value

`bigint`

Non-negative bigint to encode.

### byteLength

`number`

Required output width in bytes.

## Returns

`Uint8Array`

A `Uint8Array` padded to exactly `byteLength`.

## Throws

[InvalidPayloadError](../../core/classes/InvalidPayloadError/) When `byteLength` is not positive.

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError/) When the value is negative or does not fit
in the requested width.
