---
title: "canonicalizeJson"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / canonicalizeJson

# Function: canonicalizeJson()

> **canonicalizeJson**(`value`, `options?`): `string`

Canonically serializes JSON-compatible payloads with sorted keys and no
insignificant whitespace.

BigInt values are encoded as fixed-width lowercase hexadecimal strings.

## Parameters

### value

[`CanonicalJsonValue`](../type-aliases/CanonicalJsonValue/)

Canonical JSON value to serialize.

### options?

[`CanonicalJsonOptions`](../type-aliases/CanonicalJsonOptions/) = `{}`

Serialization options.

## Returns

`string`

Canonical JSON text.
