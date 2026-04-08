---
title: "generateParameters"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / generateParameters

# Function: generateParameters()

> **generateParameters**(`group`): [`ElgamalParameters`](../type-aliases/ElgamalParameters/)

Generates a fresh ElGamal key pair for a built-in group.

## Parameters

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput/)

Built-in group identifier that fixes `(p, q, g, h)`.

## Returns

[`ElgamalParameters`](../type-aliases/ElgamalParameters/)

Key material containing the resolved group, public and private keys.

## Throws

`UnsupportedSuiteError` When `group` does not resolve to a built-in suite.

## Example

```ts
const { publicKey, privateKey, group } = generateParameters('ffdhe3072');
```
