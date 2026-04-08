---
title: "deriveQualifiedParticipantIndices"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / deriveQualifiedParticipantIndices

# Function: deriveQualifiedParticipantIndices()

> **deriveQualifiedParticipantIndices**(`participantCount`, `acceptedComplaints`): readonly `number`[]

Derives the qualified participant set from accepted complaint outcomes.

## Parameters

### participantCount

`number`

Total participant count.

### acceptedComplaints

readonly [`ComplaintPayload`](../../protocol/type-aliases/ComplaintPayload/)[]

Complaint set resolved in the dealer-fault branch.

## Returns

readonly `number`[]

Qualified participant indices.
