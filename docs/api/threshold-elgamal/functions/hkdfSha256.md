[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / hkdfSha256

# Function: hkdfSha256()

> **hkdfSha256**(`ikm`, `salt`, `info`, `length`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Derives deterministic key material with HKDF-SHA-256.

## Parameters

### ikm

`Uint8Array`

### salt

`Uint8Array`

### info

`Uint8Array`

### length

`number`

## Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `length` is negative or not an
integer.

## Throws

[UnsupportedSuiteError](../classes/UnsupportedSuiteError.md) When Web Crypto is unavailable.
