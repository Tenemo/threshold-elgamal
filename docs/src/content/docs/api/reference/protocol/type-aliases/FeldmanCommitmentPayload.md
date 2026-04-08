---
title: "FeldmanCommitmentPayload"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [protocol](../) / FeldmanCommitmentPayload

# Type alias: FeldmanCommitmentPayload

> **FeldmanCommitmentPayload** = [`BaseProtocolPayload`](BaseProtocolPayload/) & `object`

Broadcast payload carrying Feldman commitments and coefficient proofs.

## Type declaration

### commitments

> `readonly` **commitments**: readonly `string`[]

### messageType

> `readonly` **messageType**: `"feldman-commitment"`

### proofs

> `readonly` **proofs**: readonly `object`[]
