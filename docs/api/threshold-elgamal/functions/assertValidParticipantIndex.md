[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / assertValidParticipantIndex

# Function: assertValidParticipantIndex()

> **assertValidParticipantIndex**(`index`, `participantCount`): `void`

Validates a one-based participant index against a fixed roster size.

## Parameters

### index

`number`

### participantCount

`number`

## Returns

`void`

## Throws

[IndexOutOfRangeError](../classes/IndexOutOfRangeError.md) When the index or participant count is
not an integer, or when the index falls outside `1..participantCount`.
