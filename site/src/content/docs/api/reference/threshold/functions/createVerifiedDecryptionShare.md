---
title: "createVerifiedDecryptionShare"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold](../) / createVerifiedDecryptionShare

# Function: createVerifiedDecryptionShare()

> **createVerifiedDecryptionShare**(`aggregate`, `share`, `group`): [`DecryptionShare`](../type-aliases/DecryptionShare/)

Creates a decryption share only for a locally recomputed aggregate that is
anchored to a canonical transcript hash.

## Parameters

### aggregate

[`VerifiedAggregateCiphertext`](../type-aliases/VerifiedAggregateCiphertext/)

Verified aggregate ciphertext tied to a transcript hash.

### share

[`Share`](../type-aliases/Share/)

Indexed Shamir share.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Resolved group definition.

## Returns

[`DecryptionShare`](../type-aliases/DecryptionShare/)

Partial decryption share for the verified aggregate.
