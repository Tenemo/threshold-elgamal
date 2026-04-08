---
title: "computeQual"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / computeQual

# Function: computeQual()

> **computeQual**(`participantCount`, `complaints`, `complaintResolutions?`): readonly `number`[]

Computes QUAL from the frozen participant roster and accepted complaint set.

False complainants remain in QUAL. Dealers targeted by complaints are
removed unless a dealer-authored complaint resolution matches the same
complainant, dealer, and envelope slot.

## Parameters

### participantCount

`number`

Total participant count `n`.

### complaints

readonly [`ComplaintPayload`](../../protocol/type-aliases/ComplaintPayload/)[]

Accepted complaints.

### complaintResolutions?

readonly [`ComplaintResolutionPayload`](../../protocol/type-aliases/ComplaintResolutionPayload/)[] = `[]`

Complaint resolutions already accepted into the
transcript.

## Returns

readonly `number`[]

Sorted QUAL participant indices.
