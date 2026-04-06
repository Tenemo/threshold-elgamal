[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / addEncryptedValues

# Function: addEncryptedValues()

> **addEncryptedValues**(`left`, `right`, `group`): [`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

Adds two additive-mode ciphertexts component-wise.

Use the same group and operational plaintext bound across all ciphertexts in
a tally.

## Parameters

### left

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

Left additive ciphertext.

### right

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

Right additive ciphertext.

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

Built-in group identifier shared by both ciphertexts.

## Returns

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

The additive combination of `left` and `right`.

## Example

```ts
const sum = addEncryptedValues(left, right, 'ffdhe3072');
```

## Throws

[InvalidGroupElementError](../classes/InvalidGroupElementError.md) When either ciphertext component is
outside the additive subgroup-or-identity domain.

## Throws

[UnsupportedSuiteError](../classes/UnsupportedSuiteError.md) When `group` does not resolve to a
built-in suite.
