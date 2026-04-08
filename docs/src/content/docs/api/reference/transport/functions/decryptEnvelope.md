---
title: "decryptEnvelope"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / decryptEnvelope

# Function: decryptEnvelope()

> **decryptEnvelope**(`envelope`, `recipientPrivateKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Decrypts an authenticated envelope with the recipient transport private key.

## Parameters

### envelope

[`EncryptedEnvelope`](../type-aliases/EncryptedEnvelope/)

Authenticated encrypted envelope.

### recipientPrivateKey

`string` \| `CryptoKey`

Recipient transport private key.

## Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Decrypted plaintext bytes.
