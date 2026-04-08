---
title: "wrapShareForStorage"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold](../) / wrapShareForStorage

# Function: wrapShareForStorage()

> **wrapShareForStorage**(`share`, `key`, `byteLength`): `Promise`\<[`WrappedShareRecord`](../type-aliases/WrappedShareRecord/)\>

Wraps a Shamir share value for durable local storage.

## Parameters

### share

[`Share`](../type-aliases/Share/)

Indexed Shamir share.

### key

`CryptoKey`

Non-extractable wrapping key.

### byteLength

`number`

Fixed byte width used for the share scalar encoding.

## Returns

`Promise`\<[`WrappedShareRecord`](../type-aliases/WrappedShareRecord/)\>

Wrapped share record with hex-encoded IV and ciphertext.
