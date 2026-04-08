---
title: "assertThreshold"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / assertThreshold

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

[ThresholdViolationError](../classes/ThresholdViolationError/) When the inputs are not integers or
`threshold` does not satisfy `1 <= k <= n`.
