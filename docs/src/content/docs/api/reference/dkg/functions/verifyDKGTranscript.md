---
title: "verifyDKGTranscript"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / verifyDKGTranscript

# Function: verifyDKGTranscript()

> **verifyDKGTranscript**(`input`): `Promise`\<[`VerifiedDKGTranscript`](../type-aliases/VerifiedDKGTranscript/)\>

Verifies a DKG transcript, its signatures, Feldman extraction proofs,
accepted complaint outcomes, `qualHash`, and the announced joint public key.

## Parameters

### input

[`VerifyDKGTranscriptInput`](../type-aliases/VerifyDKGTranscriptInput/)

Transcript verification input.

## Returns

`Promise`\<[`VerifiedDKGTranscript`](../type-aliases/VerifiedDKGTranscript/)\>

Verified transcript metadata and derived ceremony material.
