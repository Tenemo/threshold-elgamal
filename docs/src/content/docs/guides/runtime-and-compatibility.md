---
title: Runtime and compatibility
description: Browser, Node, Web Crypto, and BigInt expectations for the current shipped surface.
sidebar:
  order: 5
---

The current surface is browser-native and depends on two JavaScript runtime features:

- native `bigint`
- Web Crypto with `crypto.subtle` and `crypto.getRandomValues`

## Browser and Node expectations

- Modern browsers must expose Web Crypto and `bigint`
- Node must be version `24.14.1` or newer and expose `globalThis.crypto`
- The published package is ESM-only, so consumers must use `import` rather than CommonJS `require()`
- If Web Crypto is missing, the library raises `UnsupportedSuiteError`
- Transport key agreement prefers `X25519` when the runtime exposes it and falls back to `P-256` otherwise
- The shipped `ristretto255` backend is implemented with `@noble/curves` and `@noble/hashes`

## Concurrency and acceleration

- Keep Web Worker orchestration in the application. The library is designed to be imported inside workers, but it does not spawn or manage them itself.
- The root package exposes `setBigintMathBackend()` for optional backend injection. Keep the JavaScript backend as the default path and install any WASM backend explicitly from the caller.
- The current recommended default DKG regression size is `10` participants. Larger symmetric ceremonies remain much more sensitive to mobile CPU limits and connection dropouts.

## Randomness behavior

`randomBytes()` uses Web Crypto by default and fills large buffers in chunks of at most `65,536` bytes. This avoids browser quota failures from `getRandomValues()` on large requests such as `randomBytes(200000)`.

Injected custom random sources are not chunked. They are called once with the full requested length.

## BigInt caveats

- All cryptographic inputs and outputs use `bigint`
- JavaScript `bigint` arithmetic is not constant-time
- Do not mix `number` and `bigint` in arithmetic
- Serialize values explicitly when crossing process or network boundaries

## Serialization helpers

The current package ships:

- fixed-width hexadecimal helpers
- byte concatenation helpers
- injective `encodeForChallenge()` encoding for transcript and proof work

For exact function contracts, use the [API reference](../api/).
