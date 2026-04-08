[**threshold-elgamal**](../index.md)

***

[threshold-elgamal](../modules.md) / vss

# vss

Feldman and Pedersen verifiable secret sharing helpers.

This module exposes the commitment-generation and share-verification
utilities built on top of the threshold polynomial layer.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [FeldmanCommitments](type-aliases/FeldmanCommitments.md) | Feldman coefficient commitments `A_m = g^{a_m} mod p`. |
| [PedersenCommitments](type-aliases/PedersenCommitments.md) | Pedersen coefficient commitments `C_m = g^{a_m} * h^{b_m} mod p`. |
| [PedersenShare](type-aliases/PedersenShare.md) | A Pedersen share pair for one participant index. |

## Functions

| Function | Description |
| ------ | ------ |
| [derivePedersenShares](functions/derivePedersenShares.md) | Derives indexed Pedersen share pairs from matching secret and blinding polynomials. |
| [generateFeldmanCommitments](functions/generateFeldmanCommitments.md) | Computes Feldman commitments for polynomial coefficients. |
| [generatePedersenCommitments](functions/generatePedersenCommitments.md) | Computes Pedersen commitments for matching secret and blinding polynomials. |
| [verifyFeldmanShare](functions/verifyFeldmanShare.md) | Verifies a Feldman share against the published coefficient commitments. |
| [verifyPedersenShare](functions/verifyPedersenShare.md) | Verifies a Pedersen share pair against the published commitments. |
