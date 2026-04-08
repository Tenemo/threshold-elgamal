---
title: "verifyDecryptionSharePayloads"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / verifyDecryptionSharePayloads

# Function: verifyDecryptionSharePayloads()

> **verifyDecryptionSharePayloads**(`input`): `Promise`\<readonly [`VerifiedDecryptionSharePayload`](../type-aliases/VerifiedDecryptionSharePayload/)[]\>

Verifies typed decryption-share payloads against the DKG transcript-derived
trustee keys and one locally recomputed aggregate ciphertext.

Signatures are expected to have been checked already against the frozen
registration roster.

## Parameters

### input

[`VerifyDecryptionSharePayloadsInput`](../type-aliases/VerifyDecryptionSharePayloadsInput/)

Typed decryption-share verification input.

## Returns

`Promise`\<readonly [`VerifiedDecryptionSharePayload`](../type-aliases/VerifiedDecryptionSharePayload/)[]\>

Verified decryption shares ready for threshold recombination.
