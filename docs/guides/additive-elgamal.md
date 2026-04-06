# Additive ElGamal

Additive mode is the safe shipped ElGamal mode. It encrypts a plaintext `m` as `g^m`, which makes homomorphic addition possible at the ciphertext level.

## Plaintext domain

- Valid plaintexts are `0..bound`
- The bound must satisfy `0 <= bound < q`
- The same operational bound must be used when decrypting or the bounded discrete-log recovery step may fail

## Typical workflow

1. Generate key material with `generateParameters(group)`.
2. Encrypt each plaintext with `encryptAdditive(message, publicKey, group, bound)`.
3. Combine ciphertexts with `addEncryptedValues(left, right, group)`.
4. Recover the sum with `decryptAdditive(ciphertext, privateKey, group, bound)`.

## When BSGS is appropriate

The additive decrypt path uses baby-step giant-step under the hood. That is practical only when the final plaintext stays within a caller-controlled bound.

Use additive mode when:

- you know the maximum tally ahead of time
- the tally is a sum, not a product
- you want the safe root-package workflow

Do not use additive mode when:

- the decoded result could exceed any realistic bound you are willing to search
- you need threshold decryption or proofs today, because those APIs are not shipped yet

## Common mistakes

- Encrypting a value larger than `bound`
- Decrypting with a smaller bound than the tally actually needs
- Combining ciphertexts from different groups
- Assuming the library tracks or stores the bound for you

See [Groups and validation](groups-and-validation.html) for the validation helpers that back these rules.
