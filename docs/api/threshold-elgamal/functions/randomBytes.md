[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / randomBytes

# Function: randomBytes()

> **randomBytes**(`length`, `randomSource?`): `Uint8Array`

Returns cryptographically secure random bytes.

The default Web Crypto source is chunked into fills of at most 65,536 bytes
to avoid browser quota errors. Injected custom sources are called once with
the requested length.

## Parameters

### length

`number`

### randomSource?

[`RandomBytesSource`](../type-aliases/RandomBytesSource.md) = `secureRandomBytesSource`

## Returns

`Uint8Array`

## Example

```ts
const nonce = randomBytes(32);
```

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `length` is negative, not an integer,
or the injected source returns the wrong number of bytes.
