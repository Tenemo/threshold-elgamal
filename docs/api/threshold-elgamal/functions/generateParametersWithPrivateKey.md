[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / generateParametersWithPrivateKey

# Function: generateParametersWithPrivateKey()

> **generateParametersWithPrivateKey**(`privateKey`, `group`): [`ElgamalParameters`](../type-aliases/ElgamalParameters.md)

Derives the public key for a caller-supplied private scalar.

## Parameters

### privateKey

`bigint`

Private scalar in the range `1..q-1`.

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

Built-in group identifier that fixes `(p, q, g, h)`.

## Returns

[`ElgamalParameters`](../type-aliases/ElgamalParameters.md)

Key material containing the resolved group, public key, and private key.

## Throws

`InvalidScalarError` When `privateKey` is outside `1..q-1`.

## Throws

`UnsupportedSuiteError` When `group` does not resolve to a built-in suite.

## Example

```ts
const params = generateParametersWithPrivateKey(12345n, 'ffdhe3072');
```
