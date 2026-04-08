[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / combineDecryptionShares

# Function: combineDecryptionShares()

> **combineDecryptionShares**(`ciphertext`, `decryptionShares`, `group`, `bound`): `bigint`

Combines indexed decryption shares via Lagrange interpolation at `x = 0`.

## Parameters

### ciphertext

[`ElgamalCiphertext`](../../threshold-elgamal/type-aliases/ElgamalCiphertext.md)

Ciphertext being decrypted.

### decryptionShares

readonly [`DecryptionShare`](../type-aliases/DecryptionShare.md)[]

Share subset used for reconstruction.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

### bound

`bigint`

Maximum plaintext to search during additive discrete-log recovery.

## Returns

`bigint`

Recovered additive plaintext.

## Throws

When the share set is empty or contains duplicate participant
indices.

## Throws

When the recovered plaintext exceeds the supplied bound.
