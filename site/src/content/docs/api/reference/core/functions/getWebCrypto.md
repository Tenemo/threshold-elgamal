---
title: "getWebCrypto"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / getWebCrypto

# Function: getWebCrypto()

> **getWebCrypto**(): `Crypto`

Returns the runtime Web Crypto implementation used by the library.

## Returns

`Crypto`

## Throws

[UnsupportedSuiteError](../classes/UnsupportedSuiteError/) When the current runtime does not
expose `crypto.subtle` and `crypto.getRandomValues`.
