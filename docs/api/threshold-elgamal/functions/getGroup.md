[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / getGroup

# Function: getGroup()

> **getGroup**(`identifier`): [`CryptoGroup`](../type-aliases/CryptoGroup.md)

Returns one of the immutable built-in RFC 7919 group definitions.

The returned object is frozen and includes the prime-order subgroup order
`q` together with the deterministic secondary generator `h`.

## Parameters

### identifier

[`PrimeBits`](../type-aliases/PrimeBits.md) \| [`GroupName`](../type-aliases/GroupName.md)

## Returns

[`CryptoGroup`](../type-aliases/CryptoGroup.md)

## Example

```ts
const group = getGroup('ffdhe3072');
console.log(group.q > 0n);
```

## Throws

[UnsupportedSuiteError](../classes/UnsupportedSuiteError.md) When the identifier does not match one
of the built-in suites.
