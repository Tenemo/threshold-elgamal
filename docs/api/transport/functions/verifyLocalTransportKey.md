[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / verifyLocalTransportKey

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

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite.md)

Transport key-agreement suite.

## Returns

`Promise`\<`boolean`\>

`true` when the private key expands to `expectedPublicKeyHex`.
