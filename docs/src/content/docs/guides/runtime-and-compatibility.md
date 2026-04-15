---
title: Runtime and compatibility
description: Browser, Node, Web Crypto, and BigInt expectations for the honest-majority voting flow.
sidebar:
  order: 4
---

The workflow is browser-native and assumes:

- native `bigint`
- Web Crypto with `crypto.subtle` and `crypto.getRandomValues`
- ESM imports

For a concrete browser-native setup example, read [Browser and worker usage](./browser-and-worker-usage/).

## Supported environments

- Modern browsers must expose Web Crypto and `bigint`
- Node must satisfy the package `engines.node` requirement and expose `globalThis.crypto`
- If Web Crypto is missing, the library raises `UnsupportedSuiteError`
- Authentication signatures require `Ed25519`
- Transport key agreement requires `X25519`
- The tally, proof, VSS, and DKG path is fixed to `ristretto255`

## Browser requirements

The browser cryptographic path requires both Web Crypto `Ed25519` and
`X25519`.

- Use modern browsers with native `bigint`
- Require Web Crypto `Ed25519`
- Require Web Crypto `X25519`
- Validate your target environments with `pnpm exec tsx ./tools/ci/verify-browser-compat.ts`

## Application-owned runtime concerns

Keep these concerns outside the library:

- Web Worker orchestration
- wake-lock handling
- retries and polling
- mobile lifecycle handling
- local plaintext vote staging before DKG completion

The library is designed to be imported inside workers, but it does not spawn or manage them itself.

If you keep participant keys inside a worker, keep the `CryptoKey` objects in that worker unless you have verified cross-thread transfer in your target runtimes.

## Practical performance expectations

- Ceremony size materially affects CPU time, memory pressure, and network coordination
- Larger symmetric ceremonies remain much more sensitive to mobile CPU limits and connection dropouts
- Odd participant counts are recommended for clearer threshold semantics, but even counts are supported

## BigInt caveats

- All cryptographic values use `bigint`
- JavaScript `bigint` arithmetic is not constant-time
- Do not mix `number` and `bigint` in arithmetic
- Serialize values explicitly when crossing process or network boundaries

The [API docs](../api/) list exact function contracts.
