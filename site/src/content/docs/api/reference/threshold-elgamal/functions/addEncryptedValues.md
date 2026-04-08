---
title: "addEncryptedValues"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / addEncryptedValues

# Function: addEncryptedValues()

> **addEncryptedValues**(`left`, `right`, `group`): [`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext/)

Adds two additive-mode ciphertexts component-wise.

Use the same group and operational plaintext bound across all ciphertexts in
a tally.

## Parameters

### left

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext/)

Left additive ciphertext.

### right

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext/)

Right additive ciphertext.

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput/)

Built-in group identifier shared by both ciphertexts.

## Returns

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext/)

The additive combination of `left` and `right`.

## Example

```ts
const sum = addEncryptedValues(left, right, 'ffdhe3072');
```

## Throws

[InvalidGroupElementError](../../core/classes/InvalidGroupElementError/) When either ciphertext component is
outside the additive subgroup-or-identity domain.

## Throws

[UnsupportedSuiteError](../../core/classes/UnsupportedSuiteError/) When `group` does not resolve to a
built-in suite.
