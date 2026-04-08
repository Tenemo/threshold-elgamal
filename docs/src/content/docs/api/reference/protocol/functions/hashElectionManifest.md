---
title: "hashElectionManifest"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / hashElectionManifest

# Function: hashElectionManifest()

> **hashElectionManifest**(`manifest`): `Promise`\<`string`\>

Hashes a canonical election manifest with SHA-256.

## Parameters

### manifest

[`ElectionManifest`](../type-aliases/ElectionManifest/)

Election manifest to hash.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal SHA-256 digest.
