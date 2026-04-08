[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [protocol](../index.md) / hashElectionManifest

# Function: hashElectionManifest()

> **hashElectionManifest**(`manifest`): `Promise`\<`string`\>

Hashes a canonical election manifest with SHA-256.

## Parameters

### manifest

[`ElectionManifest`](../type-aliases/ElectionManifest.md)

Election manifest to hash.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal SHA-256 digest.
