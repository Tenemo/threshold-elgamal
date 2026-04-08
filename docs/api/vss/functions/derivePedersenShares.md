[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [vss](../index.md) / derivePedersenShares

# Function: derivePedersenShares()

> **derivePedersenShares**(`secretPolynomial`, `blindingPolynomial`, `participantCount`, `q`): readonly [`PedersenShare`](../type-aliases/PedersenShare.md)[]

Derives indexed Pedersen share pairs from matching secret and blinding
polynomials.

## Parameters

### secretPolynomial

[`Polynomial`](../../threshold/type-aliases/Polynomial.md)

Secret polynomial coefficients.

### blindingPolynomial

[`Polynomial`](../../threshold/type-aliases/Polynomial.md)

Blinding polynomial coefficients.

### participantCount

`number`

Total participant count.

### q

`bigint`

Prime-order subgroup order.

## Returns

readonly [`PedersenShare`](../type-aliases/PedersenShare.md)[]

Secret and blinding share pairs for `1..participantCount`.
