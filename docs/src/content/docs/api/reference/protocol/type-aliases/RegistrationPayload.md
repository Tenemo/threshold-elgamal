---
title: "RegistrationPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / RegistrationPayload

# Type alias: RegistrationPayload

> **RegistrationPayload** = [`BaseProtocolPayload`](BaseProtocolPayload/) & `object`

Registration payload carrying ceremony auth and transport keys.

## Type declaration

### authPublicKey

> `readonly` **authPublicKey**: `string`

### messageType

> `readonly` **messageType**: `"registration"`

### rosterHash

> `readonly` **rosterHash**: `string`

### transportPublicKey

> `readonly` **transportPublicKey**: `string`
