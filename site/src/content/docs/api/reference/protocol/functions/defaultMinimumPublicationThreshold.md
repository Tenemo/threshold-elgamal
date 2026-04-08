---
title: "defaultMinimumPublicationThreshold"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / defaultMinimumPublicationThreshold

# Function: defaultMinimumPublicationThreshold()

> **defaultMinimumPublicationThreshold**(`threshold`, `participantCount`): `number`

Returns the minimum publication threshold compatible with the shipped
honest-majority policy.

The manifest threshold is the reconstruction threshold `k = t + 1`, so the
small-group privacy floor `t + 2` becomes `k + 1`.

## Parameters

### threshold

`number`

Reconstruction threshold `k`.

### participantCount

`number`

Total participant count `n`.

## Returns

`number`

Minimum accepted ballot count `k + 1`.
