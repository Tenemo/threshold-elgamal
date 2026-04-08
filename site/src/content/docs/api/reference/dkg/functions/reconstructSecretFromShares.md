---
title: "reconstructSecretFromShares"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / reconstructSecretFromShares

# Function: reconstructSecretFromShares()

> **reconstructSecretFromShares**(`shares`, `q`): `bigint`

Reconstructs the polynomial constant term from indexed Shamir shares.

## Parameters

### shares

readonly [`Share`](../../threshold/type-aliases/Share/)[]

Indexed shares used for interpolation at `x = 0`.

### q

`bigint`

Prime-order subgroup order.

## Returns

`bigint`

Reconstructed constant term.
