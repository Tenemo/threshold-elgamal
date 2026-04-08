[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [vss](../index.md) / generateFeldmanCommitments

# Function: generateFeldmanCommitments()

> **generateFeldmanCommitments**(`polynomial`, `group`): [`FeldmanCommitments`](../type-aliases/FeldmanCommitments.md)

Computes Feldman commitments for polynomial coefficients.

## Parameters

### polynomial

readonly `bigint`[]

Polynomial coefficients in ascending order.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

## Returns

[`FeldmanCommitments`](../type-aliases/FeldmanCommitments.md)

Feldman commitments for every coefficient.
