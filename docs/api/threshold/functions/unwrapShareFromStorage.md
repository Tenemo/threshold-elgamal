[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / unwrapShareFromStorage

# Function: unwrapShareFromStorage()

> **unwrapShareFromStorage**(`record`, `key`): `Promise`\<[`Share`](../type-aliases/Share.md)\>

Restores a wrapped Shamir share value from local storage.

## Parameters

### record

[`WrappedShareRecord`](../type-aliases/WrappedShareRecord.md)

Wrapped share record.

### key

`CryptoKey`

Non-extractable wrapping key used during storage.

## Returns

`Promise`\<[`Share`](../type-aliases/Share.md)\>

Unwrapped indexed Shamir share.
