---
title: "assertMajorityThreshold"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / assertMajorityThreshold

# Function: assertMajorityThreshold()

> **assertMajorityThreshold**(`threshold`, `participantCount`): `number`

Validates that the supplied threshold matches the supported honest-majority
threshold `ceil(n / 2)`.

## Parameters

### threshold

`number`

Claimed reconstruction threshold.

### participantCount

`number`

Total participant count `n`.

## Returns

`number`

The validated majority threshold.

## Throws

[ThresholdViolationError](../classes/ThresholdViolationError/) When the threshold does not match the
supported honest-majority policy.
