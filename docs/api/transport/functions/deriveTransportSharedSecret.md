[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / deriveTransportSharedSecret

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

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite.md)

Transport key-agreement suite.

## Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Raw shared secret bytes.
