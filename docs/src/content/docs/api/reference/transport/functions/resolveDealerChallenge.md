---
title: "resolveDealerChallenge"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / resolveDealerChallenge

# Function: resolveDealerChallenge()

> **resolveDealerChallenge**(`envelope`, `recipientPrivateKey`, `revealedEphemeralPrivateKeyHex`): `Promise`\<[`ComplaintResolution`](../type-aliases/ComplaintResolution/)\>

Resolves a dealer challenge by revealing the sender-ephemeral private key.

If the revealed private key does not match the committed ephemeral public
key, or if the committed ciphertext still fails to decrypt, the dealer is at
fault. Successful decryption resolves the complaint in the dealer's favor.

## Parameters

### envelope

[`EncryptedEnvelope`](../type-aliases/EncryptedEnvelope/)

Committed encrypted envelope.

### recipientPrivateKey

`string` \| `CryptoKey`

Recipient transport private key.

### revealedEphemeralPrivateKeyHex

`string`

Revealed sender-ephemeral private key.

## Returns

`Promise`\<[`ComplaintResolution`](../type-aliases/ComplaintResolution/)\>

Complaint resolution result.
