[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / generateParameters

# Function: generateParameters()

> **generateParameters**(`group`): [`ElgamalParameters`](../type-aliases/ElgamalParameters.md)

Generates a fresh ElGamal key pair for a built-in group.

## Parameters

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

## Returns

[`ElgamalParameters`](../type-aliases/ElgamalParameters.md)

## Example

```ts
const { publicKey, privateKey, group } = generateParameters('ffdhe3072');
```
