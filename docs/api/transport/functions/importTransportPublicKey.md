[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / importTransportPublicKey

# Function: importTransportPublicKey()

> **importTransportPublicKey**(`publicKeyHex`, `suite`): `Promise`\<`CryptoKey`\>

Imports a transport public key from raw hexadecimal bytes.

## Parameters

### publicKeyHex

`string`

Lowercase hexadecimal public key bytes.

### suite

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite.md)

Transport key-agreement suite.

## Returns

`Promise`\<`CryptoKey`\>

Imported transport public key.
