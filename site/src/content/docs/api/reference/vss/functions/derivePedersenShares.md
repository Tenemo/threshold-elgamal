---
title: "derivePedersenShares"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [vss](../) / derivePedersenShares

# Function: derivePedersenShares()

> **derivePedersenShares**(`secretPolynomial`, `blindingPolynomial`, `participantCount`, `q`): readonly [`PedersenShare`](../type-aliases/PedersenShare/)[]

Derives indexed Pedersen share pairs from matching secret and blinding
polynomials.

## Parameters

### secretPolynomial

[`Polynomial`](../../threshold/type-aliases/Polynomial/)

Secret polynomial coefficients.

### blindingPolynomial

[`Polynomial`](../../threshold/type-aliases/Polynomial/)

Blinding polynomial coefficients.

### participantCount

`number`

Total participant count.

### q

`bigint`

Prime-order subgroup order.

## Returns

readonly [`PedersenShare`](../type-aliases/PedersenShare/)[]

Secret and blinding share pairs for `1..participantCount`.
