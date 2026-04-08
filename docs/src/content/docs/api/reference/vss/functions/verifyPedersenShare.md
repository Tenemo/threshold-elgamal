---
title: "verifyPedersenShare"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [vss](../) / verifyPedersenShare

# Function: verifyPedersenShare()

> **verifyPedersenShare**(`share`, `commitments`, `group`): `boolean`

Verifies a Pedersen share pair against the published commitments.

## Parameters

### share

[`PedersenShare`](../type-aliases/PedersenShare/)

Indexed secret and blinding share pair.

### commitments

[`PedersenCommitments`](../type-aliases/PedersenCommitments/)

Published Pedersen commitments.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Resolved group definition.

## Returns

`boolean`

`true` when the share pair matches the commitments.
