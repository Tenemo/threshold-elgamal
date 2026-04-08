[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [core](../index.md) / assertValidPublicKey

# Function: assertValidPublicKey()

> **assertValidPublicKey**(`value`, `p`, `q`): `void`

Validates a public key as a non-identity prime-order subgroup element.

## Parameters

### value

`bigint`

### p

`bigint`

### q

`bigint`

## Returns

`void`

## Throws

[InvalidGroupElementError](../classes/InvalidGroupElementError.md) When the value is not a valid
subgroup public key.
