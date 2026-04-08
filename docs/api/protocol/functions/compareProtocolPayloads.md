[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / compareProtocolPayloads

# Function: compareProtocolPayloads()

> **compareProtocolPayloads**(`left`, `right`): `number`

Deterministically compares payloads for transcript ordering.

The sort order is `phase ASC, participantIndex ASC, messageType ASC`, with
`sessionId` used as a stable prefix when cross-session payloads are mixed.

## Parameters

### left

[`ProtocolPayload`](../type-aliases/ProtocolPayload.md)

Left payload.

### right

[`ProtocolPayload`](../type-aliases/ProtocolPayload.md)

Right payload.

## Returns

`number`

Negative, zero, or positive comparison result.
