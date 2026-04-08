---
title: "DKGState"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / DKGState

# Type alias: DKGState

> **DKGState** = `object`

Snapshot of a log-driven DKG reducer state.

## Properties

### abortReason?

> `readonly` `optional` **abortReason?**: `string`

***

### complaints

> `readonly` **complaints**: readonly [`ComplaintPayload`](../../protocol/type-aliases/ComplaintPayload/)[]

***

### config

> `readonly` **config**: [`DKGConfig`](DKGConfig/)

***

### manifestAccepted

> `readonly` **manifestAccepted**: readonly `number`[]

***

### phase

> `readonly` **phase**: [`DKGPhase`](DKGPhase/)

***

### qual

> `readonly` **qual**: readonly `number`[]

***

### transcript

> `readonly` **transcript**: readonly [`SignedPayload`](../../protocol/type-aliases/SignedPayload/)[]
