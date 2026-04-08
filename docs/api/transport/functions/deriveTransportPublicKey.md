[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / deriveTransportPublicKey

# Function: deriveTransportPublicKey()

> **deriveTransportPublicKey**(`privateKey`, `suite`): `Promise`\<`string`\>

Re-derives the raw public key from a transport private key.

## Parameters

### privateKey

`CryptoKey`

Transport private key.

### suite

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite.md)

Transport key-agreement suite.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal public key bytes.
