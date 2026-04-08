---
title: "PedersenShare"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [vss](../) / PedersenShare

# Type alias: PedersenShare

> **PedersenShare** = `object`

A Pedersen share pair for one participant index.

## Properties

### blindingValue

> `readonly` **blindingValue**: `bigint`

Blinding share `b(index) mod q`.

***

### index

> `readonly` **index**: `number`

1-based participant index.

***

### secretValue

> `readonly` **secretValue**: `bigint`

Secret share `f(index) mod q`.
