---
title: "verifyAndAggregateBallots"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / verifyAndAggregateBallots

# Function: verifyAndAggregateBallots()

> **verifyAndAggregateBallots**(`input`): `Promise`\<[`VerifiedBallotAggregation`](../type-aliases/VerifiedBallotAggregation/)\>

Verifies disjunctive ballot proofs, rejects duplicate ballot slots, and
recomputes the additive aggregate deterministically.

## Parameters

### input

[`VerifyAndAggregateBallotsInput`](../type-aliases/VerifyAndAggregateBallotsInput/)

Ballot transcript verification input.

## Returns

`Promise`\<[`VerifiedBallotAggregation`](../type-aliases/VerifiedBallotAggregation/)\>

Verified aggregate and sorted accepted ballots.
