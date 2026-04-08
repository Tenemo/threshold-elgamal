[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [core](../index.md) / assertThreshold

# Function: assertThreshold()

> **assertThreshold**(`threshold`, `participantCount`): `void`

Validates threshold parameters for `k`-of-`n` protocols.

## Parameters

### threshold

`number`

### participantCount

`number`

## Returns

`void`

## Throws

[ThresholdViolationError](../classes/ThresholdViolationError.md) When the inputs are not integers or
`threshold` does not satisfy `1 <= k <= n`.
