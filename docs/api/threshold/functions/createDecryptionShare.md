[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / createDecryptionShare

# Function: createDecryptionShare()

> **createDecryptionShare**(`ciphertext`, `share`, `group`): [`DecryptionShare`](../type-aliases/DecryptionShare.md)

Creates a partial decryption share `d_i = c1^{x_i} mod p`.

Aggregate additive ciphertexts may legally have `c1 = 1`, so the first
component is validated against the subgroup-or-identity domain.

## Parameters

### ciphertext

[`ElgamalCiphertext`](../../threshold-elgamal/type-aliases/ElgamalCiphertext.md)

Ciphertext whose first component will be exponentiated.

### share

[`Share`](../type-aliases/Share.md)

Indexed Shamir share.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

## Returns

[`DecryptionShare`](../type-aliases/DecryptionShare.md)

Partial decryption share tied to `share.index`.
