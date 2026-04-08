[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / decryptEnvelope

# Function: decryptEnvelope()

> **decryptEnvelope**(`envelope`, `recipientPrivateKeyHex`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Decrypts an authenticated envelope with the recipient transport private key.

## Parameters

### envelope

[`EncryptedEnvelope`](../type-aliases/EncryptedEnvelope.md)

Authenticated encrypted envelope.

### recipientPrivateKeyHex

`string`

Recipient transport private key.

## Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Decrypted plaintext bytes.
