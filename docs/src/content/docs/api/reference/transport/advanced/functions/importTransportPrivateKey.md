---
title: "importTransportPrivateKey"
editUrl: false
---
[**threshold-elgamal**](../../../)

***

[threshold-elgamal](../../../modules/) / [transport/advanced](../) / importTransportPrivateKey

# Function: importTransportPrivateKey()

> **importTransportPrivateKey**(`privateKeyHex`, `suite`): `Promise`\<`CryptoKey`\>

Imports a transport private key from PKCS#8 hexadecimal bytes.

## Parameters

### privateKeyHex

`string`

Lowercase hexadecimal PKCS#8 bytes.

### suite

[`KeyAgreementSuite`](../../type-aliases/KeyAgreementSuite/)

Transport key-agreement suite.

## Returns

`Promise`\<`CryptoKey`\>

Imported transport private key.
