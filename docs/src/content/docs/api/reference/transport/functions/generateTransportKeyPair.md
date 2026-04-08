---
title: "generateTransportKeyPair"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / generateTransportKeyPair

# Function: generateTransportKeyPair()

> **generateTransportKeyPair**(`suiteOrOptions?`): `Promise`\<[`TransportKeyPair`](../type-aliases/TransportKeyPair/)\>

Generates a transport key pair for the requested or preferred supported
suite.

## Parameters

### suiteOrOptions?

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite/) \| [`GenerateTransportKeyPairOptions`](../type-aliases/GenerateTransportKeyPairOptions/)

Requested suite or generation options.

## Returns

`Promise`\<[`TransportKeyPair`](../type-aliases/TransportKeyPair/)\>

Transport key pair tagged with the resolved suite.
