[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [dkg](../index.md) / computeQual

# Function: computeQual()

> **computeQual**(`participantCount`, `complaints`): readonly `number`[]

Computes QUAL from the frozen participant roster and accepted complaint set.

False complainants remain in QUAL. Dealers targeted by complaints are
removed.

## Parameters

### participantCount

`number`

Total participant count `n`.

### complaints

readonly [`ComplaintPayload`](../../protocol/type-aliases/ComplaintPayload.md)[]

Accepted complaints.

## Returns

readonly `number`[]

Sorted QUAL participant indices.
