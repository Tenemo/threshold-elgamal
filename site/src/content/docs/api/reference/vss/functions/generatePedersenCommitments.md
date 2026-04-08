---
title: "generatePedersenCommitments"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [vss](../) / generatePedersenCommitments

# Function: generatePedersenCommitments()

> **generatePedersenCommitments**(`secretPolynomial`, `blindingPolynomial`, `group`): [`PedersenCommitments`](../type-aliases/PedersenCommitments/)

Computes Pedersen commitments for matching secret and blinding polynomials.

## Parameters

### secretPolynomial

readonly `bigint`[]

Secret polynomial coefficients.

### blindingPolynomial

readonly `bigint`[]

Blinding polynomial coefficients.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Resolved group definition.

## Returns

[`PedersenCommitments`](../type-aliases/PedersenCommitments/)

Pedersen commitments for every coefficient pair.
