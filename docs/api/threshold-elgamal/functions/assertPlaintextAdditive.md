[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / assertPlaintextAdditive

# Function: assertPlaintextAdditive()

> **assertPlaintextAdditive**(`value`, `bound`, `q`): `void`

Validates the plaintext domain and caller-supplied bound for additive
ElGamal.

## Parameters

### value

`bigint`

### bound

`bigint`

### q

`bigint`

## Returns

`void`

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `bound` is outside `0..q-1`.

## Throws

[PlaintextDomainError](../classes/PlaintextDomainError.md) When `value` is outside `0..bound`.
