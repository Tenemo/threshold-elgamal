---
title: "importTransportPublicKey"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / importTransportPublicKey

# Function: importTransportPublicKey()

> **importTransportPublicKey**(`publicKeyHex`, `suite`): `Promise`\<`CryptoKey`\>

Imports a transport public key from raw hexadecimal bytes.

## Parameters

### publicKeyHex

`string`

Lowercase hexadecimal public key bytes.

### suite

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite/)

Transport key-agreement suite.

## Returns

`Promise`\<`CryptoKey`\>

Imported transport public key.
