[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / encryptEnvelope

# Function: encryptEnvelope()

> **encryptEnvelope**(`plaintext`, `recipientPublicKeyHex`, `context`): `Promise`\<\{ `envelope`: [`EncryptedEnvelope`](../type-aliases/EncryptedEnvelope.md); `ephemeralPrivateKey`: `string`; \}\>

Encrypts a payload into a sender-ephemeral authenticated envelope.

## Parameters

### plaintext

`Uint8Array`

Raw payload bytes to encrypt.

### recipientPublicKeyHex

`string`

Recipient transport public key.

### context

[`EnvelopeContext`](../type-aliases/EnvelopeContext.md)

Envelope binding context.

## Returns

`Promise`\<\{ `envelope`: [`EncryptedEnvelope`](../type-aliases/EncryptedEnvelope.md); `ephemeralPrivateKey`: `string`; \}\>

Envelope plus the sender-ephemeral private key for complaint recovery.
