[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / generatePolynomial

# Function: generatePolynomial()

> **generatePolynomial**(`secret`, `threshold`, `q`): [`Polynomial`](../type-aliases/Polynomial.md)

Generates a random degree-`threshold - 1` polynomial over `Z_q`.

The constant coefficient is the shared secret. All non-constant coefficients
are sampled from `1..q-1` so the generated polynomial has the requested
degree exactly.

## Parameters

### secret

`bigint`

Secret value used as the constant coefficient.

### threshold

`number`

Reconstruction threshold `k`.

### q

`bigint`

Prime-order subgroup order.

## Returns

[`Polynomial`](../type-aliases/Polynomial.md)

Polynomial coefficients in ascending order.
