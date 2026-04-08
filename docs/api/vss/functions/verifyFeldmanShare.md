[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [vss](../index.md) / verifyFeldmanShare

# Function: verifyFeldmanShare()

> **verifyFeldmanShare**(`share`, `commitments`, `group`): `boolean`

Verifies a Feldman share against the published coefficient commitments.

## Parameters

### share

[`Share`](../../threshold/type-aliases/Share.md)

Indexed secret share.

### commitments

[`FeldmanCommitments`](../type-aliases/FeldmanCommitments.md)

Published Feldman commitments.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

## Returns

`boolean`

`true` when the share matches the commitments.
