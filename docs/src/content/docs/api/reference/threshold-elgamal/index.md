---
title: "threshold-elgamal"
description: "Generated reference page for the `threshold-elgamal` export surface."
editUrl: false
sidebar:
  order: 1
---
[**threshold-elgamal**](../)

***

[threshold-elgamal](../modules/) / threshold-elgamal

# threshold-elgamal

Safe root package exports for the current surface.

Use this entry point for group definitions, additive ElGamal, validation
helpers, and serialization helpers that are safe for the shipped package.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [ElgamalCiphertext](type-aliases/ElgamalCiphertext/) | Standard ElGamal ciphertext pair `(c1, c2)`. |
| [ElgamalGroupInput](type-aliases/ElgamalGroupInput/) | Accepted group identifier input for public ElGamal APIs. |
| [ElgamalKeyPair](type-aliases/ElgamalKeyPair/) | Public and private key pair for a selected ElGamal suite. |
| [ElgamalParameters](type-aliases/ElgamalParameters/) | Key material plus the resolved immutable group definition. |

## Functions

| Function | Description |
| ------ | ------ |
| [addEncryptedValues](functions/addEncryptedValues/) | Adds two additive-mode ciphertexts component-wise. |
| [assertValidAdditiveCiphertext](functions/assertValidAdditiveCiphertext/) | Validates an additive ciphertext that may already be an aggregate. |
| [assertValidAdditivePlaintext](functions/assertValidAdditivePlaintext/) | Validates the plaintext domain and caller-supplied bound for additive mode. |
| [assertValidAdditivePublicKey](functions/assertValidAdditivePublicKey/) | Validates an additive-mode public key against the selected group. |
| [assertValidFreshAdditiveCiphertext](functions/assertValidFreshAdditiveCiphertext/) | Validates a freshly produced additive ciphertext with subgroup `c1`. |
| [assertValidPrivateKey](functions/assertValidPrivateKey/) | Validates that a private key lies in the range `1..q-1`. |
| [babyStepGiantStep](functions/babyStepGiantStep/) | Solves a bounded discrete logarithm with the baby-step giant-step method. |
| [bigintToFixedBytes](functions/bigintToFixedBytes/) | Encodes a non-negative bigint as fixed-width big-endian bytes. |
| [bigintToFixedHex](functions/bigintToFixedHex/) | Encodes a non-negative bigint as fixed-width lowercase hexadecimal. |
| [bytesToHex](functions/bytesToHex/) | Encodes raw bytes as lowercase hexadecimal. |
| [concatBytes](functions/concatBytes/) | Concatenates multiple byte arrays into a single contiguous buffer. |
| [decryptAdditive](functions/decryptAdditive/) | Decrypts an additive ciphertext and recovers the bounded plaintext with baby-step giant-step. |
| [domainSeparator](functions/domainSeparator/) | Encodes a domain-separation tag as UTF-8 bytes. |
| [encodeForChallenge](functions/encodeForChallenge/) | Injectively encodes challenge transcript elements with 4-byte big-endian length prefixes. |
| [encodeSequenceForChallenge](functions/encodeSequenceForChallenge/) | Injectively encodes a variable-length sequence for challenge transcripts. |
| [encryptAdditive](functions/encryptAdditive/) | Encrypts an additive plaintext with fresh random `r in 1..q-1`. |
| [encryptAdditiveWithRandomness](functions/encryptAdditiveWithRandomness/) | Encrypts an additive plaintext with caller-supplied randomness. |
| [fixedHexToBigint](functions/fixedHexToBigint/) | Decodes a fixed-width hexadecimal string back into a bigint. |
| [generateParameters](functions/generateParameters/) | Generates a fresh ElGamal key pair for a built-in group. |
| [generateParametersWithPrivateKey](functions/generateParametersWithPrivateKey/) | Derives the public key for a caller-supplied private scalar. |
| [hexToBytes](functions/hexToBytes/) | Decodes a non-empty even-length hexadecimal string into bytes. |

## References

### assertInSubgroup

Re-exports [assertInSubgroup](../core/functions/assertInSubgroup/)

***

### assertInSubgroupOrIdentity

Re-exports [assertInSubgroupOrIdentity](../core/functions/assertInSubgroupOrIdentity/)

***

### assertScalarInZq

Re-exports [assertScalarInZq](../core/functions/assertScalarInZq/)

***

### assertThreshold

Re-exports [assertThreshold](../core/functions/assertThreshold/)

***

### assertValidParticipantIndex

Re-exports [assertValidParticipantIndex](../core/functions/assertValidParticipantIndex/)

***

### assertValidPublicKey

Re-exports [assertValidPublicKey](../core/functions/assertValidPublicKey/)

***

### CryptoGroup

Re-exports [CryptoGroup](../core/type-aliases/CryptoGroup/)

***

### deriveH

Re-exports [deriveH](../core/functions/deriveH/)

***

### getGroup

Re-exports [getGroup](../core/functions/getGroup/)

***

### GroupName

Re-exports [GroupName](../core/type-aliases/GroupName/)

***

### IndexOutOfRangeError

Re-exports [IndexOutOfRangeError](../core/classes/IndexOutOfRangeError/)

***

### InvalidGroupElementError

Re-exports [InvalidGroupElementError](../core/classes/InvalidGroupElementError/)

***

### InvalidPayloadError

Re-exports [InvalidPayloadError](../core/classes/InvalidPayloadError/)

***

### InvalidProofError

Re-exports [InvalidProofError](../core/classes/InvalidProofError/)

***

### InvalidScalarError

Re-exports [InvalidScalarError](../core/classes/InvalidScalarError/)

***

### InvalidShareError

Re-exports [InvalidShareError](../core/classes/InvalidShareError/)

***

### isInSubgroup

Re-exports [isInSubgroup](../core/functions/isInSubgroup/)

***

### isInSubgroupOrIdentity

Re-exports [isInSubgroupOrIdentity](../core/functions/isInSubgroupOrIdentity/)

***

### listGroups

Re-exports [listGroups](../core/functions/listGroups/)

***

### PhaseViolationError

Re-exports [PhaseViolationError](../core/classes/PhaseViolationError/)

***

### PlaintextDomainError

Re-exports [PlaintextDomainError](../core/classes/PlaintextDomainError/)

***

### PrimeBits

Re-exports [PrimeBits](../core/type-aliases/PrimeBits/)

***

### ThresholdViolationError

Re-exports [ThresholdViolationError](../core/classes/ThresholdViolationError/)

***

### TranscriptMismatchError

Re-exports [TranscriptMismatchError](../core/classes/TranscriptMismatchError/)

***

### UnsupportedSuiteError

Re-exports [UnsupportedSuiteError](../core/classes/UnsupportedSuiteError/)
