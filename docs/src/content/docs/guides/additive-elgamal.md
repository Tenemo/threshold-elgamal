---
title: Additive ElGamal
description: Bounds, plaintext domains, and tally planning for the safe shipped ElGamal workflow.
sidebar:
  order: 2
---

Additive mode is the safe shipped ElGamal mode. On the current beta line it runs on `ristretto255`, encoding a plaintext `m` as the additive scalar multiple `mG` so ciphertexts can be combined by point addition.

## Bounds and plaintext domain

- Valid plaintexts are `0..bound`
- The bound must satisfy `0 <= bound < q`
- The encryption-time bound validates only the plaintext being encrypted
- The decryption-time bound must cover the plaintext you expect to recover, which may be a larger aggregate
- Ciphertexts do not store or authenticate the bound for you

## Typical workflow

1. Generate key material with `generateParameters()`.
2. Encrypt each plaintext with `encryptAdditive(message, publicKey, messageBound)`.
3. Combine ciphertexts with `addEncryptedValues(left, right)`.
4. Recover the sum with `decryptAdditive(ciphertext, privateKey, resultBound)`.

## Planning a tally bound

For a single message, choose `bound` as the largest plaintext that message may take.

For an aggregate, choose `bound` as the largest plaintext the decrypted result may take.

Example:

- Each ballot score is in `1..10`
- A board tally combines `50` ballots
- Encrypt each ballot with `10n`
- Decrypt the final tally with `500n`

## When BSGS is appropriate

The additive decrypt path uses baby-step giant-step over Ristretto points under the hood. That is practical only when the final plaintext stays within a caller-controlled bound.

Runtime and memory both grow roughly with `sqrt(bound)`, because the solver builds a baby-step table sized to that search range.

Use additive mode when:

- you know the maximum tally ahead of time
- the tally is a sum, not a product
- you want the safe root-package workflow

Do not use additive mode when:

- the decoded result could exceed any realistic bound you are willing to search
- you need multiplicative or geometric-mean semantics, because those APIs are intentionally not shipped

For the shipped protocol voting helpers, treat `0` as out of policy even though the low-level additive primitive can represent it. The supported score-voting surface is fixed to `1..10` with no abstention encoding.

## Common mistakes

- Encrypting a value larger than the encryption-time bound
- Decrypting with a bound smaller than the tally actually needs
- Reusing one bound constant without checking whether it describes a single message or a final tally
- Combining ciphertexts from different ceremonies or public keys
- Assuming the library tracks or stores the bound for you

See [Groups and validation](./groups-and-validation/) for the validation helpers that back these rules.
