[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / dealerKeyGen

# Function: dealerKeyGen()

> **dealerKeyGen**(`threshold`, `participantCount`, `group`): [`ThresholdKeySet`](../type-aliases/ThresholdKeySet.md)

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

[`ElgamalGroupInput`](../../threshold-elgamal/type-aliases/ElgamalGroupInput.md)

Built-in group identifier used for the key material.

## Returns

[`ThresholdKeySet`](../type-aliases/ThresholdKeySet.md)

Dealer-produced threshold key material and indexed shares.
