---
title: "deriveTranscriptVerificationKey"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / deriveTranscriptVerificationKey

# Function: deriveTranscriptVerificationKey()

> **deriveTranscriptVerificationKey**(`feldmanCommitments`, `participantIndex`, `group`): `bigint`

Derives the transcript verification key `Y_j` for one participant index from
published Feldman commitments.

## Parameters

### feldmanCommitments

readonly `object`[]

Qualified dealer commitment vectors.

### participantIndex

`number`

Participant index whose key will be derived.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Selected group.

## Returns

`bigint`

Transcript-derived verification key `Y_j`.
