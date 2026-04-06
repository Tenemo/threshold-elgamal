[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / assertValidPrivateKey

# Function: assertValidPrivateKey()

> **assertValidPrivateKey**(`privateKey`, `group`): `void`

Validates that a private key lies in the range `1..q-1`.

## Parameters

### privateKey

`bigint`

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

## Returns

`void`

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError.md) When the private key is zero, negative, or
not strictly less than `q`.
