---
title: "verifyLocalTransportKey"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / verifyLocalTransportKey

# Function: verifyLocalTransportKey()

> **verifyLocalTransportKey**(`privateKey`, `expectedPublicKeyHex`, `suite`): `Promise`\<`boolean`\>

Verifies that a local transport private key matches the registered public key.

## Parameters

### privateKey

`CryptoKey`

Local transport private key.

### expectedPublicKeyHex

`string`

Registered public key bytes.

### suite

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite/)

Transport key-agreement suite.

## Returns

`Promise`\<`boolean`\>

`true` when the private key expands to `expectedPublicKeyHex`.
