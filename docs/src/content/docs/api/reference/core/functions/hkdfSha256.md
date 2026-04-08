---
title: "hkdfSha256"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / hkdfSha256

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

[InvalidScalarError](../classes/InvalidScalarError/) When `length` is negative or not an
integer.

## Throws

[UnsupportedSuiteError](../classes/UnsupportedSuiteError/) When Web Crypto is unavailable.
