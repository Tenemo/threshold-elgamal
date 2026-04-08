---
title: "generateFeldmanCommitments"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [vss](../) / generateFeldmanCommitments

# Function: generateFeldmanCommitments()

> **generateFeldmanCommitments**(`polynomial`, `group`): [`FeldmanCommitments`](../type-aliases/FeldmanCommitments/)

Computes Feldman commitments for polynomial coefficients.

## Parameters

### polynomial

readonly `bigint`[]

Polynomial coefficients in ascending order.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Resolved group definition.

## Returns

[`FeldmanCommitments`](../type-aliases/FeldmanCommitments/)

Feldman commitments for every coefficient.
