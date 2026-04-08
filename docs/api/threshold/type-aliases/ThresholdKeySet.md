[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / ThresholdKeySet

# Type alias: ThresholdKeySet

> **ThresholdKeySet** = `object`

Complete dealer-produced threshold key material.

## Properties

### group

> `readonly` **group**: [`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved built-in group definition.

***

### participantCount

> `readonly` **participantCount**: `number`

Total participant count `n`.

***

### publicKey

> `readonly` **publicKey**: `bigint`

Group public key `Y = g^s mod p`.

***

### shares

> `readonly` **shares**: readonly [`Share`](Share.md)[]

Dealer-produced shares indexed `1..n`.

***

### threshold

> `readonly` **threshold**: `number`

Reconstruction threshold `k`.
