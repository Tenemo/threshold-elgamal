---
title: "assertNonZeroSharedSecret"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / assertNonZeroSharedSecret

# Function: assertNonZeroSharedSecret()

> **assertNonZeroSharedSecret**(`sharedSecret`): `void`

Rejects all-zero key-agreement secrets.

## Parameters

### sharedSecret

`Uint8Array`

Derived shared secret bytes.

## Returns

`void`

## Throws

When the shared secret is all zero.
