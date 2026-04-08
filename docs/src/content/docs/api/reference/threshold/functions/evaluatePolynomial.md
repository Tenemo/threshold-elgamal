---
title: "evaluatePolynomial"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold](../) / evaluatePolynomial

# Function: evaluatePolynomial()

> **evaluatePolynomial**(`polynomial`, `x`, `q`): `bigint`

Evaluates a polynomial at `x` with Horner's method over `Z_q`.

## Parameters

### polynomial

[`Polynomial`](../type-aliases/Polynomial/)

Polynomial coefficients in ascending order.

### x

`bigint`

Evaluation point.

### q

`bigint`

Prime-order subgroup order.

## Returns

`bigint`

`f(x) mod q`.
