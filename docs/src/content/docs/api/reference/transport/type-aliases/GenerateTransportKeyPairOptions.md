---
title: "GenerateTransportKeyPairOptions"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / GenerateTransportKeyPairOptions

# Type alias: GenerateTransportKeyPairOptions

> **GenerateTransportKeyPairOptions** = `object`

Options controlling transport-key generation.

## Properties

### extractable?

> `readonly` `optional` **extractable?**: `boolean`

Whether the generated private key should be extractable. Defaults to `false`.

***

### suite?

> `readonly` `optional` **suite?**: [`KeyAgreementSuite`](KeyAgreementSuite/)

Requested suite, or omitted to auto-select the preferred suite.
