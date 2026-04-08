[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [core](../index.md) / assertValidParticipantIndex

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

[IndexOutOfRangeError](../classes/IndexOutOfRangeError.md) When the inputs are not integers or
`index` is outside `1..participantCount`.
