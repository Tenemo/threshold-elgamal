[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / hashProtocolTranscript

# Function: hashProtocolTranscript()

> **hashProtocolTranscript**(`payloads`, `bigintByteLength?`): `Promise`\<`string`\>

Hashes an ordered transcript of unsigned protocol payloads.

## Parameters

### payloads

readonly [`ProtocolPayload`](../type-aliases/ProtocolPayload.md)[]

Payloads to include in the transcript.

### bigintByteLength?

`number`

Fixed byte width used for any bigint fields.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal SHA-256 transcript digest.
