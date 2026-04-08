[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / signPayloadBytes

# Function: signPayloadBytes()

> **signPayloadBytes**(`privateKey`, `payloadBytes`): `Promise`\<`string`\>

Signs canonical payload bytes with an authentication private key.

## Parameters

### privateKey

`CryptoKey`

Authentication private key.

### payloadBytes

`Uint8Array`

Canonical unsigned payload bytes.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal P1363 signature bytes.
