[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [core](../index.md) / modInvP

# Function: modInvP()

> **modInvP**(`value`, `p`): `bigint`

Computes the multiplicative inverse of a value modulo `p`.

## Parameters

### value

`bigint`

### p

`bigint`

## Returns

`bigint`

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `p` is not positive or the inverse
does not exist.
