[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / deriveSharesFromPolynomial

# Function: deriveSharesFromPolynomial()

> **deriveSharesFromPolynomial**(`polynomial`, `participantCount`, `q`): readonly [`Share`](../type-aliases/Share.md)[]

Deterministically derives indexed shares from a caller-supplied polynomial.

This helper is exported for reproducible vector generation and transcript
fixtures.

## Parameters

### polynomial

[`Polynomial`](../type-aliases/Polynomial.md)

Polynomial coefficients in ascending order.

### participantCount

`number`

Total participant count `n`.

### q

`bigint`

Prime-order subgroup order.

## Returns

readonly [`Share`](../type-aliases/Share.md)[]

Indexed shares evaluated at `1..n`.
