[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / EncryptedDualSharePayload

# Type alias: EncryptedDualSharePayload

> **EncryptedDualSharePayload** = [`BaseProtocolPayload`](BaseProtocolPayload.md) & `object`

Encrypted share-envelope payload for the share-distribution step.

## Type declaration

### ciphertext

> `readonly` **ciphertext**: `string`

### envelopeId

> `readonly` **envelopeId**: `string`

### ephemeralPublicKey

> `readonly` **ephemeralPublicKey**: `string`

### iv

> `readonly` **iv**: `string`

### messageType

> `readonly` **messageType**: `"encrypted-dual-share"`

### recipientIndex

> `readonly` **recipientIndex**: `number`

### suite

> `readonly` **suite**: `"X25519"` \| `"P-256"`
