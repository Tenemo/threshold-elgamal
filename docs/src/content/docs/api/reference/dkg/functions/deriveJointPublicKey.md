---
title: "deriveJointPublicKey"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / deriveJointPublicKey

# Function: deriveJointPublicKey()

> **deriveJointPublicKey**(`feldmanCommitments`, `group`): `bigint`

Derives the qualified joint public key from the constant Feldman
commitments.

## Parameters

### feldmanCommitments

readonly `object`[]

Qualified dealer commitment vectors.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Selected group.

## Returns

`bigint`

Derived joint public key.
