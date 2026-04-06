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

### right

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

## Returns

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

## Example

```ts
const sum = addEncryptedValues(left, right, 'ffdhe3072');
```

## Throws

`InvalidCiphertextError` When either ciphertext is not valid for
additive mode.
