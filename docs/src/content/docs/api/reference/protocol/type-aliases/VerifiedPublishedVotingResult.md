---
title: "VerifiedPublishedVotingResult"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / VerifiedPublishedVotingResult

# Type alias: VerifiedPublishedVotingResult

> **VerifiedPublishedVotingResult** = `object`

Verified published tally and all of its reusable sub-results.

## Properties

### ballots

> `readonly` **ballots**: [`VerifiedBallotAggregation`](VerifiedBallotAggregation/)

***

### decryptionShares

> `readonly` **decryptionShares**: readonly [`VerifiedDecryptionSharePayload`](VerifiedDecryptionSharePayload/)[]

***

### dkg

> `readonly` **dkg**: [`VerifiedDKGTranscript`](../../dkg/type-aliases/VerifiedDKGTranscript/)

***

### tally

> `readonly` **tally**: `bigint`
