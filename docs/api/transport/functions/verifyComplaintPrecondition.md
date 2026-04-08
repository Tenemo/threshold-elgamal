[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [transport](../index.md) / verifyComplaintPrecondition

# Function: verifyComplaintPrecondition()

> **verifyComplaintPrecondition**(`privateKeyHex`, `expectedPublicKeyHex`, `suite`): `Promise`\<`boolean`\>

Verifies that the local recipient transport key still matches the registered
public key before filing a transport complaint.

## Parameters

### privateKeyHex

`string`

Recipient transport private key.

### expectedPublicKeyHex

`string`

Registered recipient public key.

### suite

[`KeyAgreementSuite`](../type-aliases/KeyAgreementSuite.md)

Transport key-agreement suite.

## Returns

`Promise`\<`boolean`\>

`true` when the local key material matches the registration.
