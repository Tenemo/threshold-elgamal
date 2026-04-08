---
title: "VerifyPublishedVotingResultInput"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / VerifyPublishedVotingResultInput

# Type alias: VerifyPublishedVotingResultInput

> **VerifyPublishedVotingResultInput** = `object`

Input bundle for verifying one full published tally.

## Properties

### ballotPayloads

> `readonly` **ballotPayloads**: readonly [`SignedPayload`](SignedPayload/)\<[`BallotSubmissionPayload`](BallotSubmissionPayload/)\>[]

***

### decryptionSharePayloads

> `readonly` **decryptionSharePayloads**: readonly [`SignedPayload`](SignedPayload/)\<[`DecryptionSharePayload`](DecryptionSharePayload/)\>[]

***

### dkgTranscript

> `readonly` **dkgTranscript**: readonly [`SignedPayload`](SignedPayload/)[]

***

### manifest

> `readonly` **manifest**: [`ElectionManifest`](ElectionManifest/)

***

### protocol

> `readonly` **protocol**: [`DKGProtocol`](../../dkg/type-aliases/DKGProtocol/)

***

### sessionId

> `readonly` **sessionId**: `string`

***

### tallyPublication?

> `readonly` `optional` **tallyPublication?**: [`SignedPayload`](SignedPayload/)\<[`TallyPublicationPayload`](TallyPublicationPayload/)\>
