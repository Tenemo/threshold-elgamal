[threshold-elgamal](index.md) / Exports

# threshold-elgamal

## Table of contents

### Type Aliases

- [EncryptedMessage](modules.md#encryptedmessage)
- [KeyPair](modules.md#keypair)
- [Parameters](modules.md#parameters)
- [PartyKeyPair](modules.md#partykeypair)

### Functions

- [combineDecryptionShares](modules.md#combinedecryptionshares)
- [combinePublicKeys](modules.md#combinepublickeys)
- [createDecryptionShare](modules.md#createdecryptionshare)
- [decrypt](modules.md#decrypt)
- [encrypt](modules.md#encrypt)
- [generateKeyShares](modules.md#generatekeyshares)
- [generateParameters](modules.md#generateparameters)
- [generateSingleKeyShare](modules.md#generatesinglekeyshare)
- [getGroup](modules.md#getgroup)
- [getRandomBigIntegerInRange](modules.md#getrandombigintegerinrange)
- [multiplyEncryptedValues](modules.md#multiplyencryptedvalues)
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

[types.ts:1](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/types.ts#L1)

___

### KeyPair

Ƭ **KeyPair**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `privateKey` | `bigint` |
| `publicKey` | `bigint` |

#### Defined in

[types.ts:13](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/types.ts#L13)

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

[types.ts:6](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/types.ts#L6)

___

### PartyKeyPair

Ƭ **PartyKeyPair**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `partyPrivateKey` | `bigint` |
| `partyPublicKey` | `bigint` |

#### Defined in

[types.ts:18](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/types.ts#L18)

## Functions

### combineDecryptionShares

▸ **combineDecryptionShares**(`decryptionShares`, `prime`): `bigint`

Combines partial decryptions from multiple parties into a single decryption factor.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `decryptionShares` | `bigint`[] | An array of partial decryption results. |
| `prime` | `bigint` | The prime modulus used in the ElGamal system. |

#### Returns

`bigint`

The combined decryption factor.

#### Defined in

[thresholdElgamal.ts:107](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/thresholdElgamal.ts#L107)

___

### combinePublicKeys

▸ **combinePublicKeys**(`publicKeys`, `prime`): `bigint`

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

[thresholdElgamal.ts:81](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/thresholdElgamal.ts#L81)

___

### createDecryptionShare

▸ **createDecryptionShare**(`encryptedMessage`, `partyPrivateKey`, `prime`): `bigint`

Performs a partial decryption on a ciphertext using an individual's private key share.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `encryptedMessage` | [`EncryptedMessage`](modules.md#encryptedmessage) | The encrypted secret. |
| `partyPrivateKey` | `bigint` | The private key share of the decrypting party. |
| `prime` | `bigint` | The prime modulus used in the ElGamal system. |

#### Returns

`bigint`

The result of the partial decryption.

#### Defined in

[thresholdElgamal.ts:94](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/thresholdElgamal.ts#L94)

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

[elgamal.ts:58](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/elgamal.ts#L58)

___

### encrypt

▸ **encrypt**(`secret`, `prime`, `generator`, `publicKey`): [`EncryptedMessage`](modules.md#encryptedmessage)

Encrypts a secret using ElGamal encryption.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `secret` | `number` | The secret to be encrypted. |
| `prime` | `bigint` | The prime number used in the encryption system. |
| `generator` | `bigint` | The generator used in the encryption system. |
| `publicKey` | `bigint` | The public key used for encryption. |

#### Returns

[`EncryptedMessage`](modules.md#encryptedmessage)

The encrypted secret, consisting of two BigIntegers (c1 and c2).

#### Defined in

[elgamal.ts:32](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/elgamal.ts#L32)

___

### generateKeyShares

▸ **generateKeyShares**(`n`, `threshold`, `primeBits?`): [`PartyKeyPair`](modules.md#partykeypair)[]

Generates key shares for a threshold ElGamal cryptosystem.

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `n` | `number` | `undefined` | The total number of key shares. |
| `threshold` | `number` | `undefined` | The minimum number of key shares required for decryption. |
| `primeBits` | ``2048`` \| ``3072`` \| ``4096`` | `2048` | The bit length of the prime modulus (default: 2048). |

#### Returns

[`PartyKeyPair`](modules.md#partykeypair)[]

An array of key shares, each containing a private and public key share.

#### Defined in

[thresholdElgamal.ts:61](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/thresholdElgamal.ts#L61)

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

[elgamal.ts:13](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/elgamal.ts#L13)

___

### generateSingleKeyShare

▸ **generateSingleKeyShare**(`index`, `threshold`, `primeBits?`): [`PartyKeyPair`](modules.md#partykeypair)

Generates a single key share for a participant in a threshold ElGamal cryptosystem.

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `index` | `number` | `undefined` | The unique index of the participant (starting from 1). |
| `threshold` | `number` | `undefined` | The minimum number of key shares required for decryption. |
| `primeBits` | ``2048`` \| ``3072`` \| ``4096`` | `2048` | The bit length of the prime modulus (default: 2048). |

#### Returns

[`PartyKeyPair`](modules.md#partykeypair)

The key share containing a private and public key share for the participant.

#### Defined in

[thresholdElgamal.ts:34](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/thresholdElgamal.ts#L34)

___

### getGroup

▸ **getGroup**(`primeBits`): `Object`

Retrieves the group parameters for a given prime bit length.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `primeBits` | ``2048`` \| ``3072`` \| ``4096`` | The bit length of the prime modulus (2048, 3072, or 4096). |

#### Returns

`Object`

The group parameters including prime and generator.

| Name | Type |
| :------ | :------ |
| `generator` | `bigint` |
| `prime` | `bigint` |

#### Defined in

[utils.ts:12](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/utils.ts#L12)

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

[utils.ts:33](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/utils.ts#L33)

___

### multiplyEncryptedValues

▸ **multiplyEncryptedValues**(`value1`, `value2`, `prime`): [`EncryptedMessage`](modules.md#encryptedmessage)

Performs homomorphic multiplication on two encrypted values, allowing for encrypted arithmetic operations.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `value1` | [`EncryptedMessage`](modules.md#encryptedmessage) | The first encrypted value. |
| `value2` | [`EncryptedMessage`](modules.md#encryptedmessage) | The second encrypted value. |
| `prime` | `bigint` | The prime modulus used in the encryption system. |

#### Returns

[`EncryptedMessage`](modules.md#encryptedmessage)

The result of the multiplication, as a new encrypted message.

#### Defined in

[utils.ts:55](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/utils.ts#L55)

___

### thresholdDecrypt

▸ **thresholdDecrypt**(`encryptedMessage`, `combinedDecryptionShares`, `prime`): `number`

Decrypts an encrypted secret using the combined partial decryptions in a threshold ElGamal scheme.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `encryptedMessage` | `Object` | The encrypted secret components. |
| `encryptedMessage.c1` | `bigint` | - |
| `encryptedMessage.c2` | `bigint` | - |
| `combinedDecryptionShares` | `bigint` | The combined partial decryptions from all parties. |
| `prime` | `bigint` | The prime modulus used in the ElGamal system. |

#### Returns

`number`

The decrypted secret, assuming it was small enough to be directly encrypted.

#### Defined in

[thresholdElgamal.ts:126](https://github.com/Tenemo/threshold-elgamal/blob/53231c5ef06b9fac8e430a0185260ee7a32941cb/src/thresholdElgamal.ts#L126)
