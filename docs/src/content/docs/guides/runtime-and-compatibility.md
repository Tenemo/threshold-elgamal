---
title: Runtime and compatibility
description: Browser, Node, Web Crypto, and BigInt expectations for the shipped honest-majority voting flow.
sidebar:
  order: 4
---

The shipped workflow is browser-native and assumes:

- native `bigint`
- Web Crypto with `crypto.subtle` and `crypto.getRandomValues`
- ESM imports

## Supported environments

- Modern browsers must expose Web Crypto and `bigint`
- Node must be version `24.14.1` or newer and expose `globalThis.crypto`
- If Web Crypto is missing, the library raises `UnsupportedSuiteError`
- Transport key agreement prefers `X25519` when available and falls back to `P-256`
- The tally, proof, VSS, and DKG path is fixed to `ristretto255`

## Application-owned runtime concerns

Keep these concerns outside the library:

- Web Worker orchestration
- wake-lock handling
- retries and polling
- mobile lifecycle handling
- local plaintext vote staging before DKG completion

The library is designed to be imported inside workers, but it does not spawn or manage them itself.

## Practical performance expectations

- The current default regression ceremony size is `10` participants
- Larger symmetric ceremonies remain much more sensitive to mobile CPU limits and connection dropouts
- Odd participant counts are recommended for clearer threshold semantics, but even counts are supported

## BigInt caveats

- All cryptographic values use `bigint`
- JavaScript `bigint` arithmetic is not constant-time
- Do not mix `number` and `bigint` in arithmetic
- Serialize values explicitly when crossing process or network boundaries

For exact function contracts, use the [API docs](../api/).
