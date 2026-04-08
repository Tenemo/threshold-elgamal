---
title: "VerifyAndAggregateBallotsInput"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / VerifyAndAggregateBallotsInput

# Type alias: VerifyAndAggregateBallotsInput

> **VerifyAndAggregateBallotsInput** = `object`

Input bundle for ballot verification and aggregation.

## Properties

### ballots

> `readonly` **ballots**: readonly [`BallotTranscriptEntry`](BallotTranscriptEntry/)[]

***

### group

> `readonly` **group**: [`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

***

### label?

> `readonly` `optional` **label?**: `string`

***

### manifestHash

> `readonly` **manifestHash**: `string`

***

### minimumBallotCount

> `readonly` **minimumBallotCount**: `number`

***

### publicKey

> `readonly` **publicKey**: `bigint`

***

### sessionId

> `readonly` **sessionId**: `string`

***

### validValues

> `readonly` **validValues**: readonly `bigint`[]
