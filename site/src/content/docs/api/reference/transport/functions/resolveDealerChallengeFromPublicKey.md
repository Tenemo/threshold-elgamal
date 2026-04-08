---
title: "resolveDealerChallengeFromPublicKey"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / resolveDealerChallengeFromPublicKey

# Function: resolveDealerChallengeFromPublicKey()

> **resolveDealerChallengeFromPublicKey**(`envelope`, `recipientPublicKeyHex`, `revealedEphemeralPrivateKeyHex`): `Promise`\<[`ComplaintResolution`](../type-aliases/ComplaintResolution/)\>

Resolves a dealer challenge using only public transcript material plus the
dealer-revealed sender-ephemeral private key.

## Parameters

### envelope

[`EncryptedEnvelope`](../type-aliases/EncryptedEnvelope/)

Committed encrypted envelope.

### recipientPublicKeyHex

`string`

Registered recipient transport public key.

### revealedEphemeralPrivateKeyHex

`string`

Revealed sender-ephemeral private key.

## Returns

`Promise`\<[`ComplaintResolution`](../type-aliases/ComplaintResolution/)\>

Complaint resolution result.
