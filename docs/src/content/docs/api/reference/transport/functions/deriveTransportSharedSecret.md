---
title: "deriveTransportSharedSecret"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / deriveTransportSharedSecret

# Function: deriveTransportSharedSecret()

> **deriveTransportSharedSecret**(`privateKey`, `publicKey`, `suite`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Derives a raw shared secret for the selected transport suite.

## Parameters

### privateKey

`CryptoKey`

Local transport private key.

### publicKey

`CryptoKey`

Peer transport public key.

### suite

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite/)

Transport key-agreement suite.

## Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Raw shared secret bytes.
