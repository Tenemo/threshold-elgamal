[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [vss](../index.md) / verifyPedersenShare

# Function: verifyPedersenShare()

> **verifyPedersenShare**(`share`, `commitments`, `group`): `boolean`

Verifies a Pedersen share pair against the published commitments.

## Parameters

### share

[`PedersenShare`](../type-aliases/PedersenShare.md)

Indexed secret and blinding share pair.

### commitments

[`PedersenCommitments`](../type-aliases/PedersenCommitments.md)

Published Pedersen commitments.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

## Returns

`boolean`

`true` when the share pair matches the commitments.
