[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / generateParametersWithPrivateKey

# Function: generateParametersWithPrivateKey()

> **generateParametersWithPrivateKey**(`privateKey`, `group`): [`ElgamalParameters`](../type-aliases/ElgamalParameters.md)

Derives the public key for a caller-supplied private scalar.

## Parameters

### privateKey

`bigint`

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

## Returns

[`ElgamalParameters`](../type-aliases/ElgamalParameters.md)

## Throws

`InvalidScalarError` When `privateKey` is outside `1..q-1`.

## Example

```ts
const params = generateParametersWithPrivateKey(12345n, 'ffdhe3072');
```
