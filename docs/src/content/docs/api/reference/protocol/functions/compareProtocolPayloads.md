---
title: "compareProtocolPayloads"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / compareProtocolPayloads

# Function: compareProtocolPayloads()

> **compareProtocolPayloads**(`left`, `right`): `number`

Deterministically compares payloads for transcript ordering.

The sort order is `sessionId ASC, phase ASC, participantIndex ASC,
messageType ASC`, followed by message-type-specific slot fields and finally
canonical payload bytes to guarantee a total order.

## Parameters

### left

[`ProtocolPayload`](../type-aliases/ProtocolPayload/)

Left payload.

### right

[`ProtocolPayload`](../type-aliases/ProtocolPayload/)

Right payload.

## Returns

`number`

Negative, zero, or positive comparison result.
