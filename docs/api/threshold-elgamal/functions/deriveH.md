[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / deriveH

# Function: deriveH()

> **deriveH**(`input`): `Promise`\<`bigint`\>

Derives the deterministic secondary subgroup generator `h` for a built-in
suite.

The derivation uses HKDF expand-and-square until it finds a subgroup element
distinct from both the identity and `g`.

## Parameters

### input

[`PrimeBits`](../type-aliases/PrimeBits.md) \| [`GroupName`](../type-aliases/GroupName.md)

Built-in suite identifier by bit size or canonical group name.

## Returns

`Promise`\<`bigint`\>

The derived subgroup generator `h` for the selected suite.

## Throws

[UnsupportedSuiteError](../classes/UnsupportedSuiteError.md) When the identifier does not match one
of the built-in suites.
