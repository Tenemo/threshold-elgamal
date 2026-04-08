---
title: "verifyBallotSubmissionPayloads"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / verifyBallotSubmissionPayloads

# Function: verifyBallotSubmissionPayloads()

> **verifyBallotSubmissionPayloads**(`input`): `Promise`\<[`VerifiedBallotAggregation`](../type-aliases/VerifiedBallotAggregation/)\>

Verifies typed ballot-submission payloads and recomputes the aggregate tally
ciphertext from the accepted ballot transcript.

Signatures are expected to have been checked already against the frozen
registration roster.

## Parameters

### input

[`VerifyBallotSubmissionPayloadsInput`](../type-aliases/VerifyBallotSubmissionPayloadsInput/)

Typed ballot verification input.

## Returns

`Promise`\<[`VerifiedBallotAggregation`](../type-aliases/VerifiedBallotAggregation/)\>

Verified additive ballot aggregation.
