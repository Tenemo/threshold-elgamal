---
title: "VerifiedDKGTranscript"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / VerifiedDKGTranscript

# Type alias: VerifiedDKGTranscript

> **VerifiedDKGTranscript** = `object`

Verified DKG transcript result with reusable derived ceremony material.

## Properties

### acceptedComplaints

> `readonly` **acceptedComplaints**: readonly [`ComplaintPayload`](../../protocol/type-aliases/ComplaintPayload/)[]

***

### derivedPublicKey

> `readonly` **derivedPublicKey**: `bigint`

***

### feldmanCommitments

> `readonly` **feldmanCommitments**: readonly `object`[]

***

### group

> `readonly` **group**: [`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

***

### qual

> `readonly` **qual**: readonly `number`[]

***

### qualHash

> `readonly` **qualHash**: `string`

***

### registrations

> `readonly` **registrations**: readonly [`SignedPayload`](../../protocol/type-aliases/SignedPayload/)\<[`RegistrationPayload`](../../protocol/type-aliases/RegistrationPayload/)\>[]

***

### rosterHash

> `readonly` **rosterHash**: `string`
