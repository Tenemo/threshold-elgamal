---
title: "deriveSharesFromPolynomial"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold](../) / deriveSharesFromPolynomial

# Function: deriveSharesFromPolynomial()

> **deriveSharesFromPolynomial**(`polynomial`, `participantCount`, `q`): readonly [`Share`](../type-aliases/Share/)[]

Deterministically derives indexed shares from a caller-supplied polynomial.

This helper is exported for reproducible vector generation and transcript
fixtures.

## Parameters

### polynomial

[`Polynomial`](../type-aliases/Polynomial/)

Polynomial coefficients in ascending order.

### participantCount

`number`

Total participant count `n`.

### q

`bigint`

Prime-order subgroup order.

## Returns

readonly [`Share`](../type-aliases/Share/)[]

Indexed shares evaluated at `1..n`.
