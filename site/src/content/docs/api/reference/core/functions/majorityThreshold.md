---
title: "majorityThreshold"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / majorityThreshold

# Function: majorityThreshold()

> **majorityThreshold**(`participantCount`): `number`

Derives the supported honest-majority threshold `ceil(n / 2)`.

## Parameters

### participantCount

`number`

Total participant count `n`.

## Returns

`number`

Supported reconstruction threshold `k`.

## Throws

[ThresholdViolationError](../classes/ThresholdViolationError/) When `participantCount` is not a
positive integer.
