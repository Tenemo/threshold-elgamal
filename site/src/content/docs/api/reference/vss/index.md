---
title: "vss"
description: "Generated reference page for the `vss` export surface."
editUrl: false
sidebar:
  order: 4
---
[**threshold-elgamal**](../)

***

[threshold-elgamal](../modules/) / vss

# vss

Feldman and Pedersen verifiable secret sharing helpers.

This module exposes the commitment-generation and share-verification
utilities built on top of the threshold polynomial layer.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [FeldmanCommitments](type-aliases/FeldmanCommitments/) | Feldman coefficient commitments `A_m = g^{a_m} mod p`. |
| [PedersenCommitments](type-aliases/PedersenCommitments/) | Pedersen coefficient commitments `C_m = g^{a_m} * h^{b_m} mod p`. |
| [PedersenShare](type-aliases/PedersenShare/) | A Pedersen share pair for one participant index. |

## Functions

| Function | Description |
| ------ | ------ |
| [derivePedersenShares](functions/derivePedersenShares/) | Derives indexed Pedersen share pairs from matching secret and blinding polynomials. |
| [generateFeldmanCommitments](functions/generateFeldmanCommitments/) | Computes Feldman commitments for polynomial coefficients. |
| [generatePedersenCommitments](functions/generatePedersenCommitments/) | Computes Pedersen commitments for matching secret and blinding polynomials. |
| [verifyFeldmanShare](functions/verifyFeldmanShare/) | Verifies a Feldman share against the published coefficient commitments. |
| [verifyPedersenShare](functions/verifyPedersenShare/) | Verifies a Pedersen share pair against the published commitments. |
