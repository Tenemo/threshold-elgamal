---
title: "verifyFeldmanShare"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [vss](../) / verifyFeldmanShare

# Function: verifyFeldmanShare()

> **verifyFeldmanShare**(`share`, `commitments`, `group`): `boolean`

Verifies a Feldman share against the published coefficient commitments.

## Parameters

### share

[`Share`](../../threshold/type-aliases/Share/)

Indexed secret share.

### commitments

[`FeldmanCommitments`](../type-aliases/FeldmanCommitments/)

Published Feldman commitments.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Resolved group definition.

## Returns

`boolean`

`true` when the share matches the commitments.
