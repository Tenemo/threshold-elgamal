---
title: "signPayloadBytes"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / signPayloadBytes

# Function: signPayloadBytes()

> **signPayloadBytes**(`privateKey`, `payloadBytes`): `Promise`\<`string`\>

Signs canonical payload bytes with an authentication private key.

## Parameters

### privateKey

`CryptoKey`

Authentication private key.

### payloadBytes

`Uint8Array`

Canonical unsigned payload bytes.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal raw P1363 `r || s` signature bytes.
