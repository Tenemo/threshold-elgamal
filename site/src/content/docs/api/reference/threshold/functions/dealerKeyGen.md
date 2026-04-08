---
title: "dealerKeyGen"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold](../) / dealerKeyGen

# Function: dealerKeyGen()

> **dealerKeyGen**(`threshold`, `participantCount`, `group`): [`ThresholdKeySet`](../type-aliases/ThresholdKeySet/)

Splits a fresh secret into indexed Shamir shares and derives the threshold
public key for dealer-based threshold decryption.

## Parameters

### threshold

`number`

Reconstruction threshold `k`.

### participantCount

`number`

Total participant count `n`.

### group

[`ElgamalGroupInput`](../../threshold-elgamal/type-aliases/ElgamalGroupInput/)

Built-in group identifier used for the key material.

## Returns

[`ThresholdKeySet`](../type-aliases/ThresholdKeySet/)

Dealer-produced threshold key material and indexed shares.
