---
title: "hashAcceptedBallots"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / hashAcceptedBallots

# Function: hashAcceptedBallots()

> **hashAcceptedBallots**(`ballots`, `group`): `Promise`\<`string`\>

Hashes the accepted ballot transcript deterministically.

## Parameters

### ballots

readonly [`BallotTranscriptEntry`](../type-aliases/BallotTranscriptEntry/)[]

Verified ballot records.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Selected group definition.

## Returns

`Promise`\<`string`\>

Lowercase hexadecimal transcript hash.
