---
title: "verifyComplaintPrecondition"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [transport](../) / verifyComplaintPrecondition

# Function: verifyComplaintPrecondition()

> **verifyComplaintPrecondition**(`privateKey`, `expectedPublicKeyHex`, `suite`): `Promise`\<`boolean`\>

Verifies that the local recipient transport key still matches the registered
public key before filing a transport complaint.

## Parameters

### privateKey

`string` \| `CryptoKey`

Recipient transport private key.

### expectedPublicKeyHex

`string`

Registered recipient public key.

### suite

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite/)

Transport key-agreement suite.

## Returns

`Promise`\<`boolean`\>

`true` when the local key material matches the registration.
