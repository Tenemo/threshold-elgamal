[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / Share

# Type alias: Share

> **Share** = `object`

A single indexed Shamir share over `Z_q`.

## Properties

### index

> `readonly` **index**: `number`

1-based participant index.

***

### value

> `readonly` **value**: `bigint`

Share value `f(index) mod q`.
