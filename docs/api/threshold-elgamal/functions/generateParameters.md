[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / generateParameters

# Function: generateParameters()

> **generateParameters**(`group`): [`ElgamalParameters`](../type-aliases/ElgamalParameters.md)

Generates a fresh ElGamal key pair for a built-in group.

## Parameters

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

Built-in group identifier that fixes `(p, q, g, h)`.

## Returns

[`ElgamalParameters`](../type-aliases/ElgamalParameters.md)

Key material containing the resolved group, public and private keys.

## Throws

`UnsupportedSuiteError` When `group` does not resolve to a built-in suite.

## Example

```ts
const { publicKey, privateKey, group } = generateParameters('ffdhe3072');
```
