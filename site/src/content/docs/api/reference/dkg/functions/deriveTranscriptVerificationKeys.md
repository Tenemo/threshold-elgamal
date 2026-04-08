---
title: "deriveTranscriptVerificationKeys"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / deriveTranscriptVerificationKeys

# Function: deriveTranscriptVerificationKeys()

> **deriveTranscriptVerificationKeys**(`feldmanCommitments`, `participantIndices`, `group`): readonly `object`[]

Derives transcript verification keys for multiple participant indices.

## Parameters

### feldmanCommitments

readonly `object`[]

Qualified dealer commitment vectors.

### participantIndices

readonly `number`[]

Participant indices to derive.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Selected group.

## Returns

readonly `object`[]

Indexed transcript-derived verification keys.
