[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [dkg](../index.md) / DKGState

# Type alias: DKGState

> **DKGState** = `object`

Snapshot of a log-driven DKG reducer state.

## Properties

### abortReason?

> `readonly` `optional` **abortReason?**: `string`

***

### complaints

> `readonly` **complaints**: readonly [`ComplaintPayload`](../../protocol/type-aliases/ComplaintPayload.md)[]

***

### config

> `readonly` **config**: [`DKGConfig`](DKGConfig.md)

***

### manifestAccepted

> `readonly` **manifestAccepted**: readonly `number`[]

***

### phase

> `readonly` **phase**: [`DKGPhase`](DKGPhase.md)

***

### qual

> `readonly` **qual**: readonly `number`[]

***

### transcript

> `readonly` **transcript**: readonly [`SignedPayload`](../../protocol/type-aliases/SignedPayload.md)[]
