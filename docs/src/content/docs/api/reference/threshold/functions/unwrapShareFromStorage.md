---
title: "unwrapShareFromStorage"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold](../) / unwrapShareFromStorage

# Function: unwrapShareFromStorage()

> **unwrapShareFromStorage**(`record`, `key`): `Promise`\<[`Share`](../type-aliases/Share/)\>

Restores a wrapped Shamir share value from local storage.

## Parameters

### record

[`WrappedShareRecord`](../type-aliases/WrappedShareRecord/)

Wrapped share record.

### key

`CryptoKey`

Non-extractable wrapping key used during storage.

## Returns

`Promise`\<[`Share`](../type-aliases/Share/)\>

Unwrapped indexed Shamir share.
