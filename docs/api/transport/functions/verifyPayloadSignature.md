[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / verifyPayloadSignature

# Function: verifyPayloadSignature()

> **verifyPayloadSignature**(`publicKey`, `payloadBytes`, `signatureHex`): `Promise`\<`boolean`\>

Verifies canonical payload bytes against a P-256 authentication signature.

## Parameters

### publicKey

`CryptoKey`

Authentication public key.

### payloadBytes

`Uint8Array`

Canonical unsigned payload bytes.

### signatureHex

`string`

Lowercase hexadecimal P1363 signature bytes.

## Returns

`Promise`\<`boolean`\>

`true` when the signature verifies.
