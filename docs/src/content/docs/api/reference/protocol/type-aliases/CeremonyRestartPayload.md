---
title: "CeremonyRestartPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / CeremonyRestartPayload

# Type alias: CeremonyRestartPayload

> **CeremonyRestartPayload** = [`BaseProtocolPayload`](BaseProtocolPayload/) & `object`

Signed link from a restarted ceremony to the aborted prior attempt.

## Type declaration

### messageType

> `readonly` **messageType**: `"ceremony-restart"`

### previousSessionId

> `readonly` **previousSessionId**: `string`

### previousTranscriptHash

> `readonly` **previousTranscriptHash**: `string`

### reason

> `readonly` **reason**: [`RestartReasonCode`](RestartReasonCode/)
