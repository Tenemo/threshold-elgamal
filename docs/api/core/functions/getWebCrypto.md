[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [core](../index.md) / getWebCrypto

# Function: getWebCrypto()

> **getWebCrypto**(): `Crypto`

Returns the runtime Web Crypto implementation used by the library.

## Returns

`Crypto`

## Throws

[UnsupportedSuiteError](../classes/UnsupportedSuiteError.md) When the current runtime does not
expose `crypto.subtle` and `crypto.getRandomValues`.
