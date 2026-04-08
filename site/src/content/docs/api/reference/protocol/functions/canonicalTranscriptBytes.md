---
title: "canonicalTranscriptBytes"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / canonicalTranscriptBytes

# Function: canonicalTranscriptBytes()

> **canonicalTranscriptBytes**(`payloads`, `bigintByteLength?`): `Uint8Array`

Canonically serializes the ordered unsigned payload set for a transcript.

## Parameters

### payloads

readonly [`ProtocolPayload`](../type-aliases/ProtocolPayload/)[]

Payloads to include in the transcript.

### bigintByteLength?

`number`

Fixed byte width used for any bigint fields.

## Returns

`Uint8Array`

Canonical transcript bytes.
