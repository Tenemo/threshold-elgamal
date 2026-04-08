---
title: "VerifiedAggregateCiphertext"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold](../) / VerifiedAggregateCiphertext

# Type alias: VerifiedAggregateCiphertext

> **VerifiedAggregateCiphertext** = `object`

A threshold aggregate tied to a verified additive ciphertext.

## Properties

### \[verifiedAggregateBrand\]

> `readonly` **\[verifiedAggregateBrand\]**: `true`

Opaque brand preventing arbitrary object-literal construction.

***

### ballotCount

> `readonly` **ballotCount**: `number`

Number of accepted ciphertexts that contributed to the aggregate.

***

### ciphertext

> `readonly` **ciphertext**: [`ElgamalCiphertext`](../../threshold-elgamal/type-aliases/ElgamalCiphertext/)

Aggregate ciphertext recomputed from the accepted ballot log.

***

### transcriptHash

> `readonly` **transcriptHash**: `string`

Canonical transcript hash that anchors the accepted ballot log.
