[**threshold-elgamal**](../index.md)

***

[threshold-elgamal](../modules.md) / threshold-elgamal

# threshold-elgamal

Safe root package exports for the current surface.

Use this entry point for group definitions, additive ElGamal, validation
helpers, and serialization helpers that are safe for the shipped package.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [ElgamalCiphertext](type-aliases/ElgamalCiphertext.md) | Standard ElGamal ciphertext pair `(c1, c2)`. |
| [ElgamalGroupInput](type-aliases/ElgamalGroupInput.md) | Accepted group identifier input for public ElGamal APIs. |
| [ElgamalKeyPair](type-aliases/ElgamalKeyPair.md) | Public and private key pair for a selected ElGamal suite. |
| [ElgamalParameters](type-aliases/ElgamalParameters.md) | Key material plus the resolved immutable group definition. |

## Functions

| Function | Description |
| ------ | ------ |
| [addEncryptedValues](functions/addEncryptedValues.md) | Adds two additive-mode ciphertexts component-wise. |
| [assertValidAdditiveCiphertext](functions/assertValidAdditiveCiphertext.md) | Validates an additive ciphertext that may already be an aggregate. |
| [assertValidAdditivePlaintext](functions/assertValidAdditivePlaintext.md) | Validates the plaintext domain and caller-supplied bound for additive mode. |
| [assertValidAdditivePublicKey](functions/assertValidAdditivePublicKey.md) | Validates an additive-mode public key against the selected group. |
| [assertValidFreshAdditiveCiphertext](functions/assertValidFreshAdditiveCiphertext.md) | Validates a freshly produced additive ciphertext with subgroup `c1`. |
| [assertValidPrivateKey](functions/assertValidPrivateKey.md) | Validates that a private key lies in the range `1..q-1`. |
| [babyStepGiantStep](functions/babyStepGiantStep.md) | Solves a bounded discrete logarithm with the baby-step giant-step method. |
| [bigintToFixedHex](functions/bigintToFixedHex.md) | Encodes a non-negative bigint as fixed-width lowercase hexadecimal. |
| [bytesToHex](functions/bytesToHex.md) | Encodes raw bytes as lowercase hexadecimal. |
| [concatBytes](functions/concatBytes.md) | Concatenates multiple byte arrays into a single contiguous buffer. |
| [decryptAdditive](functions/decryptAdditive.md) | Decrypts an additive ciphertext and recovers the bounded plaintext with baby-step giant-step. |
| [domainSeparator](functions/domainSeparator.md) | Encodes a domain-separation tag as UTF-8 bytes. |
| [encodeForChallenge](functions/encodeForChallenge.md) | Injectively encodes challenge transcript elements with 4-byte big-endian length prefixes. |
| [encryptAdditive](functions/encryptAdditive.md) | Encrypts an additive plaintext with fresh random `r in 1..q-1`. |
| [encryptAdditiveWithRandomness](functions/encryptAdditiveWithRandomness.md) | Encrypts an additive plaintext with caller-supplied randomness. |
| [fixedHexToBigint](functions/fixedHexToBigint.md) | Decodes a fixed-width hexadecimal string back into a bigint. |
| [generateParameters](functions/generateParameters.md) | Generates a fresh ElGamal key pair for a built-in group. |
| [generateParametersWithPrivateKey](functions/generateParametersWithPrivateKey.md) | Derives the public key for a caller-supplied private scalar. |
| [hexToBytes](functions/hexToBytes.md) | Decodes a non-empty even-length hexadecimal string into bytes. |

## References

### assertInSubgroup

Re-exports [assertInSubgroup](../core/functions/assertInSubgroup.md)

***

### assertInSubgroupOrIdentity

Re-exports [assertInSubgroupOrIdentity](../core/functions/assertInSubgroupOrIdentity.md)

***

### assertScalarInZq

Re-exports [assertScalarInZq](../core/functions/assertScalarInZq.md)

***

### assertValidPublicKey

Re-exports [assertValidPublicKey](../core/functions/assertValidPublicKey.md)

***

### CryptoGroup

Re-exports [CryptoGroup](../core/type-aliases/CryptoGroup.md)

***

### getGroup

Re-exports [getGroup](../core/functions/getGroup.md)

***

### GroupName

Re-exports [GroupName](../core/type-aliases/GroupName.md)

***

### InvalidGroupElementError

Re-exports [InvalidGroupElementError](../core/classes/InvalidGroupElementError.md)

***

### InvalidPayloadError

Re-exports [InvalidPayloadError](../core/classes/InvalidPayloadError.md)

***

### InvalidScalarError

Re-exports [InvalidScalarError](../core/classes/InvalidScalarError.md)

***

### isInSubgroup

Re-exports [isInSubgroup](../core/functions/isInSubgroup.md)

***

### isInSubgroupOrIdentity

Re-exports [isInSubgroupOrIdentity](../core/functions/isInSubgroupOrIdentity.md)

***

### listGroups

Re-exports [listGroups](../core/functions/listGroups.md)

***

### PlaintextDomainError

Re-exports [PlaintextDomainError](../core/classes/PlaintextDomainError.md)

***

### PrimeBits

Re-exports [PrimeBits](../core/type-aliases/PrimeBits.md)

***

### UnsupportedSuiteError

Re-exports [UnsupportedSuiteError](../core/classes/UnsupportedSuiteError.md)
