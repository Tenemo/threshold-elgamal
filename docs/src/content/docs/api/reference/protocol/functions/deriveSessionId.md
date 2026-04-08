---
title: "deriveSessionId"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / deriveSessionId

# Function: deriveSessionId()

> **deriveSessionId**(`manifestHash`, `rosterHash`, `randomNonce`, `timestamp`): `Promise`\<`string`\>

Derives a globally unique session identifier from the frozen setup values.

## Parameters

### manifestHash

`string`

Canonical manifest hash.

### rosterHash

`string`

Canonical roster hash.

### randomNonce

`string`

Public random nonce.

### timestamp

`string`

Timestamp string included in the derivation.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal SHA-256 digest.
