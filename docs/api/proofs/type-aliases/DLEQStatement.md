[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [proofs](../index.md) / DLEQStatement

# Type alias: DLEQStatement

> **DLEQStatement** = `object`

Statement tuple for a Chaum-Pedersen equality-of-discrete-logs proof.

## Properties

### ciphertext

> `readonly` **ciphertext**: [`ElgamalCiphertext`](../../threshold-elgamal/type-aliases/ElgamalCiphertext.md)

Ciphertext being partially decrypted.

***

### decryptionShare

> `readonly` **decryptionShare**: `bigint`

Partial decryption share `d_j = c1^{x_j} mod p`.

***

### publicKey

> `readonly` **publicKey**: `bigint`

Transcript-derived trustee verification key.
