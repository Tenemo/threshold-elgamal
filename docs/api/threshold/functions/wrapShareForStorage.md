[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / wrapShareForStorage

# Function: wrapShareForStorage()

> **wrapShareForStorage**(`share`, `key`, `byteLength`): `Promise`\<[`WrappedShareRecord`](../type-aliases/WrappedShareRecord.md)\>

Wraps a Shamir share value for durable local storage.

## Parameters

### share

[`Share`](../type-aliases/Share.md)

Indexed Shamir share.

### key

`CryptoKey`

Non-extractable wrapping key.

### byteLength

`number`

Fixed byte width used for the share scalar encoding.

## Returns

`Promise`\<[`WrappedShareRecord`](../type-aliases/WrappedShareRecord.md)\>

Wrapped share record with hex-encoded IV and ciphertext.
