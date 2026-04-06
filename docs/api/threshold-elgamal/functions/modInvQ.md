[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / modInvQ

# Function: modInvQ()

> **modInvQ**(`value`, `q`): `bigint`

Computes the multiplicative inverse of a value modulo `q`.

## Parameters

### value

`bigint`

### q

`bigint`

## Returns

`bigint`

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `q` is not positive or the inverse
does not exist.
