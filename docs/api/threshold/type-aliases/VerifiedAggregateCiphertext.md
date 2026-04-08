[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / VerifiedAggregateCiphertext

# Type alias: VerifiedAggregateCiphertext

> **VerifiedAggregateCiphertext** = `object`

A threshold aggregate tied to a verified additive ciphertext.

## Properties

### ciphertext

> `readonly` **ciphertext**: [`ElgamalCiphertext`](../../threshold-elgamal/type-aliases/ElgamalCiphertext.md)

Aggregate ciphertext recomputed from the accepted ballot log.

***

### transcriptHash

> `readonly` **transcriptHash**: `string`

Canonical transcript hash that anchors the accepted ballot log.
