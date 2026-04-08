---
title: "deriveTransportPublicKey"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / deriveTransportPublicKey

# Function: deriveTransportPublicKey()

> **deriveTransportPublicKey**(`privateKey`, `suite`): `Promise`\<`string`\>

Re-derives the raw public key from a transport private key.

## Parameters

### privateKey

`CryptoKey`

Transport private key.

### suite

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite/)

Transport key-agreement suite.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal public key bytes.
