[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / resolveDealerChallenge

# Function: resolveDealerChallenge()

> **resolveDealerChallenge**(`envelope`, `recipientPrivateKeyHex`, `revealedEphemeralPrivateKeyHex`): `Promise`\<[`ComplaintResolution`](../type-aliases/ComplaintResolution.md)\>

Resolves a dealer challenge by revealing the sender-ephemeral private key.

If the revealed private key does not match the committed ephemeral public
key, or if the committed ciphertext still fails to decrypt, the dealer is at
fault. Successful decryption resolves the complaint in the dealer's favor.

## Parameters

### envelope

[`EncryptedEnvelope`](../type-aliases/EncryptedEnvelope.md)

Committed encrypted envelope.

### recipientPrivateKeyHex

`string`

Recipient transport private key.

### revealedEphemeralPrivateKeyHex

`string`

Revealed sender-ephemeral private key.

## Returns

`Promise`\<[`ComplaintResolution`](../type-aliases/ComplaintResolution.md)\>

Complaint resolution result.
