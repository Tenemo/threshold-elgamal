---
title: "verifySignedProtocolPayloads"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / verifySignedProtocolPayloads

# Function: verifySignedProtocolPayloads()

> **verifySignedProtocolPayloads**(`signedPayloads`, `participantCount?`): `Promise`\<[`VerifiedProtocolSignatures`](../type-aliases/VerifiedProtocolSignatures/)\>

Verifies protocol payload signatures against the registration roster carried
in the transcript.

Registration signatures are verified against the auth key embedded in the
same registration payload. Every later payload is verified against the
registered auth key for its participant index.

## Parameters

### signedPayloads

readonly [`SignedPayload`](../type-aliases/SignedPayload/)[]

Signed protocol payloads.

### participantCount?

`number`

Optional expected participant count.

## Returns

`Promise`\<[`VerifiedProtocolSignatures`](../type-aliases/VerifiedProtocolSignatures/)\>

Verified registration roster and derived roster hash.
