[threshold-elgamal](index.md) / Exports

# threshold-elgamal

## Table of contents

### Type Aliases

- [EncryptedMessage](modules.md#encryptedmessage)
- [Parameters](modules.md#parameters)

### Functions

- [combineDecryptionShares](modules.md#combinedecryptionshares)
- [combinePublicKeys](modules.md#combinepublickeys)
- [createDecryptionShare](modules.md#createdecryptionshare)
- [decrypt](modules.md#decrypt)
- [deserializeEncryptedMessage](modules.md#deserializeencryptedmessage)
- [encrypt](modules.md#encrypt)
- [generateKeyShares](modules.md#generatekeyshares)
- [generateKeys](modules.md#generatekeys)
- [generateParameters](modules.md#generateparameters)
- [getGroup](modules.md#getgroup)
- [getRandomBigIntegerInRange](modules.md#getrandombigintegerinrange)
- [multiplyEncryptedValues](modules.md#multiplyencryptedvalues)
- [serializeEncryptedMessage](modules.md#serializeencryptedmessage)
- [thresholdDecrypt](modules.md#thresholddecrypt)

## Type Aliases

### EncryptedMessage

Ƭ **EncryptedMessage**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `c1` | `bigint` |
| `c2` | `bigint` |

#### Defined in

[types.ts:1](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/types.ts#L1)

___

### Parameters

Ƭ **Parameters**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `generator` | `bigint` |
| `prime` | `bigint` |
| `privateKey` | `bigint` |
| `publicKey` | `bigint` |

#### Defined in

[types.ts:6](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/types.ts#L6)

## Functions

### combineDecryptionShares

▸ **combineDecryptionShares**(`decryptionShares`, `prime?`): `bigint`

Combines partial decryptions from multiple parties into a single decryption factor.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `decryptionShares` | `bigint`[] | An array of partial decryption results. |
| `prime` | `bigint` | The prime modulus used in the ElGamal system. Defaults to the 2048-bit group prime. |

#### Returns

`bigint`

The combined decryption factor.

#### Defined in

[thresholdElgamal.ts:111](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/thresholdElgamal.ts#L111)

___

### combinePublicKeys

▸ **combinePublicKeys**(`publicKeys`, `prime?`): `bigint`

Combines multiple public keys into a single public key.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `publicKeys` | `bigint`[] | An array of public keys to combine. |
| `prime` | `bigint` | The prime modulus used in the ElGamal system. |

#### Returns

`bigint`

The combined public key.

#### Defined in

[thresholdElgamal.ts:81](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/thresholdElgamal.ts#L81)

___

### createDecryptionShare

▸ **createDecryptionShare**(`encryptedMessage`, `privateKey`, `prime?`): `bigint`

Performs a partial decryption on a ciphertext using an individual's private key share.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `encryptedMessage` | [`EncryptedMessage`](modules.md#encryptedmessage) | The encrypted secret. |
| `privateKey` | `bigint` | The private key share of the decrypting party. |
| `prime` | `bigint` | The prime modulus used in the ElGamal system. Defaults to the 2048-bit group prime. |

#### Returns

`bigint`

The result of the partial decryption.

#### Defined in

[thresholdElgamal.ts:98](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/thresholdElgamal.ts#L98)

___

### decrypt

▸ **decrypt**(`encryptedMessage`, `prime`, `privateKey`): `number`

Decrypts an ElGamal encrypted secret.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `encryptedMessage` | [`EncryptedMessage`](modules.md#encryptedmessage) | - |
| `prime` | `bigint` | The prime number used in the encryption system. |
| `privateKey` | `bigint` | The private key used for decryption. |

#### Returns

`number`

The decrypted secret as an integer.

#### Defined in

[elgamal.ts:58](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/elgamal.ts#L58)

___

### deserializeEncryptedMessage

▸ **deserializeEncryptedMessage**(`message`): [`EncryptedMessage`](modules.md#encryptedmessage)

Deserializes an object containing string representations of an encrypted message's components
back into an `EncryptedMessage` with bigint components. This is useful for reconstructing
encrypted messages from their stringified forms, such as when retrieving them from JSON data.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `message` | `Object` | An object containing the `c1` and `c2` components of the message as strings. |
| `message.c1` | `string` | - |
| `message.c2` | `string` | - |

#### Returns

[`EncryptedMessage`](modules.md#encryptedmessage)

The deserialized encrypted message with `c1` and `c2` as bigints.

**`Example`**

```ts
// An example serialized message
const serializedMessage = { c1: "1234567890123456789012345678901234567890", c2: "0987654321098765432109876543210987654321" };
const encryptedMessage = deserializeEncryptedMessage(serializedMessage);
console.log(encryptedMessage); // Output: { c1: 1234567890123456789012345678901234567890n, c2: 0987654321098765432109876543210987654321n }
```

#### Defined in

[utils/utils.ts:155](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/utils/utils.ts#L155)

___

### encrypt

▸ **encrypt**(`secret`, `publicKey`, `prime?`, `generator?`): [`EncryptedMessage`](modules.md#encryptedmessage)

Encrypts a secret using ElGamal encryption.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `secret` | `number` | The secret to be encrypted. |
| `publicKey` | `bigint` | The public key used for encryption. |
| `prime` | `bigint` | The prime number used in the encryption system. Defaults to the 2048-bit group's prime. |
| `generator` | `bigint` | The generator used in the encryption system. Defaults to the 2048-bit group's generator. |

#### Returns

[`EncryptedMessage`](modules.md#encryptedmessage)

The encrypted secret, consisting of two BigIntegers (c1 and c2).

#### Defined in

[elgamal.ts:32](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/elgamal.ts#L32)

___

### generateKeyShares

▸ **generateKeyShares**(`n`, `threshold`, `primeBits?`): \{ `privateKey`: `bigint` ; `publicKey`: `bigint`  }[]

Generates key shares for a threshold ElGamal cryptosystem.

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `n` | `number` | `undefined` | The total number of key shares. |
| `threshold` | `number` | `undefined` | The minimum number of key shares required for decryption. |
| `primeBits` | ``2048`` \| ``3072`` \| ``4096`` | `2048` | The bit length of the prime modulus (default: 2048). |

#### Returns

\{ `privateKey`: `bigint` ; `publicKey`: `bigint`  }[]

An array of key shares, each containing a private and public key share.

#### Defined in

[thresholdElgamal.ts:61](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/thresholdElgamal.ts#L61)

___

### generateKeys

▸ **generateKeys**(`index`, `threshold`, `primeBits?`): `Object`

Generates a single key share for a participant in a threshold ElGamal cryptosystem.

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `index` | `number` | `undefined` | The unique index of the participant (starting from 1). |
| `threshold` | `number` | `undefined` | The minimum number of key shares required for decryption. |
| `primeBits` | ``2048`` \| ``3072`` \| ``4096`` | `2048` | The bit length of the prime modulus (default: 2048). |

#### Returns

`Object`

The key share containing a private and public key share for the participant.

| Name | Type |
| :------ | :------ |
| `privateKey` | `bigint` |
| `publicKey` | `bigint` |

#### Defined in

[thresholdElgamal.ts:34](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/thresholdElgamal.ts#L34)

___

### generateParameters

▸ **generateParameters**(`primeBits?`): [`Parameters`](modules.md#parameters)

Generates the parameters for the ElGamal encryption, including the prime, generator,
and key pair (public and private keys).

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `primeBits` | ``2048`` \| ``3072`` \| ``4096`` | `2048` | The bit length for the prime number. Supports 2048, 3072, or 4096 bits. |

#### Returns

[`Parameters`](modules.md#parameters)

The generated parameters including the prime, generator, publicKey, and privateKey.

#### Defined in

[elgamal.ts:13](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/elgamal.ts#L13)

___

### getGroup

▸ **getGroup**(`primeBits?`): `Object`

Retrieves the group parameters for a given prime bit length.

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `primeBits` | ``2048`` \| ``3072`` \| ``4096`` | `2048` | The bit length of the prime modulus (2048, 3072, or 4096). |

#### Returns

`Object`

The group parameters including prime and generator.

| Name | Type |
| :------ | :------ |
| `generator` | `bigint` |
| `prime` | `bigint` |

#### Defined in

[utils/utils.ts:47](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/utils/utils.ts#L47)

___

### getRandomBigIntegerInRange

▸ **getRandomBigIntegerInRange**(`min`, `max`): `bigint`

Generates a random bigint within a specified range.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `min` | `bigint` | The minimum value (inclusive). |
| `max` | `bigint` | The maximum value (exclusive). |

#### Returns

`bigint`

A random bigint within the specified range.

#### Defined in

[utils/utils.ts:68](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/utils/utils.ts#L68)

___

### multiplyEncryptedValues

▸ **multiplyEncryptedValues**(`value1`, `value2`, `prime?`): [`EncryptedMessage`](modules.md#encryptedmessage)

Performs homomorphic multiplication on two encrypted values, allowing for encrypted arithmetic operations.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `value1` | [`EncryptedMessage`](modules.md#encryptedmessage) | The first encrypted value. |
| `value2` | [`EncryptedMessage`](modules.md#encryptedmessage) | The second encrypted value. |
| `prime` | `bigint` | The prime modulus used in the encryption system. Defaults to the 2048-bit group prime. |

#### Returns

[`EncryptedMessage`](modules.md#encryptedmessage)

The result of the multiplication, as a new encrypted message.

#### Defined in

[utils/utils.ts:90](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/utils/utils.ts#L90)

___

### serializeEncryptedMessage

▸ **serializeEncryptedMessage**(`message`): `Object`

Serializes an encrypted message into an object with string representations of its components.
This function is useful for converting the bigint components of an encrypted message into
strings, making them easier to store or transmit as JSON, for instance.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `message` | [`EncryptedMessage`](modules.md#encryptedmessage) | The encrypted message to be serialized. It should have two bigint properties: `c1` and `c2`. |

#### Returns

`Object`

An object containing the `c1` and `c2` components of the message as strings.

| Name | Type |
| :------ | :------ |
| `c1` | `string` |
| `c2` | `string` |

**`Example`**

```ts
// An example encrypted message
const encryptedMessage = { c1: BigInt('1234567890123456789012345678901234567890'), c2: BigInt('0987654321098765432109876543210987654321') };
const serializedMessage = serializeEncryptedMessage(encryptedMessage);
console.log(serializedMessage); // Output: { c1: "1234567890123456789012345678901234567890", c2: "0987654321098765432109876543210987654321" }
```

#### Defined in

[utils/utils.ts:134](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/utils/utils.ts#L134)

___

### thresholdDecrypt

▸ **thresholdDecrypt**(`encryptedMessage`, `combinedDecryptionShares`, `prime?`): `number`

Decrypts an encrypted secret using the combined partial decryptions in a threshold ElGamal scheme.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `encryptedMessage` | `Object` | The encrypted secret components. |
| `encryptedMessage.c1` | `bigint` | - |
| `encryptedMessage.c2` | `bigint` | - |
| `combinedDecryptionShares` | `bigint` | The combined partial decryptions from all parties. |
| `prime` | `bigint` | The prime modulus used in the ElGamal system. Defaults to the 2048-bit group prime. |

#### Returns

`number`

The decrypted secret, assuming it was small enough to be directly encrypted.

#### Defined in

[thresholdElgamal.ts:130](https://github.com/Tenemo/threshold-elgamal/blob/48382fcd0efef2ed7870bca11815f4031a4ff7f6/src/thresholdElgamal.ts#L130)
