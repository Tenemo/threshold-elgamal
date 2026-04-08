[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [vss](../index.md) / generatePedersenCommitments

# Function: generatePedersenCommitments()

> **generatePedersenCommitments**(`secretPolynomial`, `blindingPolynomial`, `group`): [`PedersenCommitments`](../type-aliases/PedersenCommitments.md)

Computes Pedersen commitments for matching secret and blinding polynomials.

## Parameters

### secretPolynomial

readonly `bigint`[]

Secret polynomial coefficients.

### blindingPolynomial

readonly `bigint`[]

Blinding polynomial coefficients.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

## Returns

[`PedersenCommitments`](../type-aliases/PedersenCommitments.md)

Pedersen commitments for every coefficient pair.
