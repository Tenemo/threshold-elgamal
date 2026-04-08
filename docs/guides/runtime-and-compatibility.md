# Runtime and compatibility

The current surface is browser-native and depends on two JavaScript runtime features:

- native `bigint`
- Web Crypto with `crypto.subtle` and `crypto.getRandomValues`

## Browser and Node expectations

- Modern browsers must expose Web Crypto and `bigint`
- Node must be version `24.14.1` or newer and expose `globalThis.crypto`
- The published package is ESM-only, so consumers must use `import` rather than CommonJS `require()`
- If Web Crypto is missing, the library raises `UnsupportedSuiteError`
- Transport key agreement prefers `X25519` when the runtime exposes it and
  falls back to `P-256` otherwise

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
- injective `encodeForChallenge()` encoding for future transcript and proof work

For exact function contracts, use the [API reference](../api/index.html).
