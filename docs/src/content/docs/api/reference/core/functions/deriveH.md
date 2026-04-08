---
title: "deriveH"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / deriveH

# Function: deriveH()

> **deriveH**(`identifier`): `Promise`\<`bigint`\>

Recomputes the deterministic secondary generator `h` for a built-in suite.

The derivation uses HKDF-SHA-256 over a suite-specific seed string, then
maps the result into `2..p-2` before squaring into the prime-order subgroup.

## Parameters

### identifier

[`PrimeBits`](../type-aliases/PrimeBits/) \| [`GroupName`](../type-aliases/GroupName/)

Built-in suite identifier by bit size or canonical group name.

## Returns

`Promise`\<`bigint`\>

The recomputed deterministic subgroup generator `h`.

## Throws

[UnsupportedSuiteError](../classes/UnsupportedSuiteError/) When the identifier does not match one
of the built-in suites.

## Throws

[InvalidGroupElementError](../classes/InvalidGroupElementError/) When the derived value violates the
expected subgroup invariants.
