---
title: "hashRosterEntries"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / hashRosterEntries

# Function: hashRosterEntries()

> **hashRosterEntries**(`rosterEntries`): `Promise`\<`string`\>

Hashes a deterministic roster view with SHA-256.

## Parameters

### rosterEntries

readonly [`RosterEntry`](../type-aliases/RosterEntry/)[]

Deterministic roster entries.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal roster hash.
