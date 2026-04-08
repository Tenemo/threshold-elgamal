[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / generateTransportKeyPair

# Function: generateTransportKeyPair()

> **generateTransportKeyPair**(`suite?`): `Promise`\<[`TransportKeyPair`](../type-aliases/TransportKeyPair.md)\>

Generates a transport key pair for the requested or preferred supported
suite.

## Parameters

### suite?

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite.md)

Requested suite, or omitted to auto-select the preferred suite.

## Returns

`Promise`\<[`TransportKeyPair`](../type-aliases/TransportKeyPair.md)\>

Transport key pair tagged with the resolved suite.
