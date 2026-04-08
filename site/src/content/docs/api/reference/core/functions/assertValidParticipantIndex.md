---
title: "assertValidParticipantIndex"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / assertValidParticipantIndex

# Function: assertValidParticipantIndex()

> **assertValidParticipantIndex**(`index`, `participantCount`): `void`

Validates a 1-based participant index for a fixed participant count.

## Parameters

### index

`number`

### participantCount

`number`

## Returns

`void`

## Throws

[IndexOutOfRangeError](../classes/IndexOutOfRangeError/) When the inputs are not integers or
`index` is outside `1..participantCount`.
