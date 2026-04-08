---
title: "verifyPublishedVotingResult"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / verifyPublishedVotingResult

# Function: verifyPublishedVotingResult()

> **verifyPublishedVotingResult**(`input`): `Promise`\<[`VerifiedPublishedVotingResult`](../type-aliases/VerifiedPublishedVotingResult/)\>

Verifies one published tally from the signed DKG log, typed ballot payloads,
typed decryption-share payloads, and an optional tally-publication record.

The helper intentionally recomputes everything locally: it verifies the DKG
transcript, recomputes the aggregate from the accepted ballots, verifies each
DLEQ proof against transcript-derived trustee keys, and only then combines
shares into the final tally.

## Parameters

### input

[`VerifyPublishedVotingResultInput`](../type-aliases/VerifyPublishedVotingResultInput/)

Published tally verification input.

## Returns

`Promise`\<[`VerifiedPublishedVotingResult`](../type-aliases/VerifiedPublishedVotingResult/)\>

Fully verified tally result.
