[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / assertThreshold

# Function: assertThreshold()

> **assertThreshold**(`threshold`, `participantCount`): `void`

Validates a threshold `k` against a participant count `n`.

## Parameters

### threshold

`number`

### participantCount

`number`

## Returns

`void`

## Throws

[ThresholdViolationError](../classes/ThresholdViolationError.md) When either input is not an integer
or when `k` falls outside `1..n`.
