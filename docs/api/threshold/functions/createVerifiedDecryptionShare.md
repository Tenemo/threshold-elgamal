[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / createVerifiedDecryptionShare

# Function: createVerifiedDecryptionShare()

> **createVerifiedDecryptionShare**(`aggregate`, `share`, `group`): [`DecryptionShare`](../type-aliases/DecryptionShare.md)

Creates a decryption share only for a locally recomputed aggregate that is
anchored to a canonical transcript hash.

## Parameters

### aggregate

[`VerifiedAggregateCiphertext`](../type-aliases/VerifiedAggregateCiphertext.md)

Verified aggregate ciphertext tied to a transcript hash.

### share

[`Share`](../type-aliases/Share.md)

Indexed Shamir share.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

## Returns

[`DecryptionShare`](../type-aliases/DecryptionShare.md)

Partial decryption share for the verified aggregate.
