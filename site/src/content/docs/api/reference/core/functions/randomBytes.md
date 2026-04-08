---
title: "randomBytes"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / randomBytes

# Function: randomBytes()

> **randomBytes**(`length`, `randomSource?`): `Uint8Array`

Returns cryptographically secure random bytes.

The default Web Crypto source is chunked into fills of at most 65,536 bytes
to avoid browser quota errors. Injected custom sources are called once with
the requested length.

## Parameters

### length

`number`

Number of random bytes to return.

### randomSource?

[`RandomBytesSource`](../type-aliases/RandomBytesSource/) = `secureRandomBytesSource`

Optional injected random source used for deterministic tests or custom runtimes.

## Returns

`Uint8Array`

A `Uint8Array` with exactly `length` random bytes.

## Example

```ts
const nonce = randomBytes(32);
```

## Throws

[InvalidScalarError](../classes/InvalidScalarError/) When `length` is negative, not an integer,
or the injected source returns the wrong number of bytes.

## Throws

[UnsupportedSuiteError](../classes/UnsupportedSuiteError/) When the default Web Crypto source is
unavailable in the current runtime.
