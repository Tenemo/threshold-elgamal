---
title: "ProofContext"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [proofs](../) / ProofContext

# Type alias: ProofContext

> **ProofContext** = `object`

Common Fiat-Shamir context fields used by the shipped proof systems.

## Properties

### coefficientIndex?

> `readonly` `optional` **coefficientIndex?**: `number`

Optional coefficient index for Feldman coefficient proofs.

***

### label

> `readonly` **label**: `string`

Domain-separation label for the proof domain.

***

### manifestHash

> `readonly` **manifestHash**: `string`

Canonical election-manifest hash or equivalent protocol root.

***

### optionIndex?

> `readonly` `optional` **optionIndex?**: `number`

Optional ballot option index for ballot proofs.

***

### participantIndex?

> `readonly` `optional` **participantIndex?**: `number`

Optional participant index for trustee-bound proofs.

***

### protocolVersion

> `readonly` **protocolVersion**: `string`

Protocol version string bound into the transcript.

***

### sessionId

> `readonly` **sessionId**: `string`

Ceremony or transcript session identifier.

***

### suiteId

> `readonly` **suiteId**: [`GroupName`](../../core/type-aliases/GroupName/)

Group suite name bound into the transcript.

***

### voterIndex?

> `readonly` `optional` **voterIndex?**: `number`

Optional voter index for ballot proofs.
