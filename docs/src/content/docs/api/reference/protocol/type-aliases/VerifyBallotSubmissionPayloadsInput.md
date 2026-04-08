---
title: "VerifyBallotSubmissionPayloadsInput"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / VerifyBallotSubmissionPayloadsInput

# Type alias: VerifyBallotSubmissionPayloadsInput

> **VerifyBallotSubmissionPayloadsInput** = `object`

Input bundle for verifying typed ballot payloads.

## Properties

### ballotPayloads

> `readonly` **ballotPayloads**: readonly [`SignedPayload`](SignedPayload/)\<[`BallotSubmissionPayload`](BallotSubmissionPayload/)\>[]

***

### manifest

> `readonly` **manifest**: [`ElectionManifest`](ElectionManifest/)

***

### publicKey

> `readonly` **publicKey**: `bigint`

***

### sessionId

> `readonly` **sessionId**: `string`
