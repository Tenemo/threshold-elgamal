[**threshold-elgamal**](../index.md)

***

[threshold-elgamal](../modules.md) / threshold-elgamal

# threshold-elgamal

Safe root package exports for the current surface.

Use this entry point for group definitions, additive ElGamal, validation
helpers, and serialization helpers that are safe for the shipped package.

## Classes

| Class | Description |
| ------ | ------ |
| [IndexOutOfRangeError](classes/IndexOutOfRangeError.md) | Raised when a participant index falls outside the allowed roster range. |
| [InvalidCiphertextError](classes/InvalidCiphertextError.md) | Reserved exported error class for future ciphertext-shape APIs. |
| [InvalidGroupElementError](classes/InvalidGroupElementError.md) | Raised when a group element is not valid for the selected finite-field suite. |
| [InvalidPayloadError](classes/InvalidPayloadError.md) | Raised when serialized payload bytes do not satisfy the required encoding. |
| [InvalidProofError](classes/InvalidProofError.md) | Reserved exported error class for future proof-oriented APIs. |
| [InvalidScalarError](classes/InvalidScalarError.md) | Raised when a scalar value falls outside the expected mathematical domain. |
| [InvalidShareError](classes/InvalidShareError.md) | Reserved exported error class for future share-oriented APIs. |
| [PhaseViolationError](classes/PhaseViolationError.md) | Reserved exported error class for future protocol phase APIs. |
| [PlaintextDomainError](classes/PlaintextDomainError.md) | Raised when a plaintext lies outside the allowed domain for the chosen mode. |
| [ThresholdViolationError](classes/ThresholdViolationError.md) | Raised when threshold or participant-count constraints are violated. |
| [TranscriptMismatchError](classes/TranscriptMismatchError.md) | Reserved exported error class for future transcript-matching APIs. |
| [UnsupportedSuiteError](classes/UnsupportedSuiteError.md) | Raised when the requested suite or runtime capability is unavailable. |

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [Brand](type-aliases/Brand.md) | Nominal typing helper used to distinguish compatible runtime values in the type system. |
| [CryptoGroup](type-aliases/CryptoGroup.md) | Immutable built-in group definition exposed by `getGroup()` and keygen APIs. |
| [ElgamalCiphertext](type-aliases/ElgamalCiphertext.md) | Standard ElGamal ciphertext pair `(c1, c2)`. |
| [ElgamalGroupInput](type-aliases/ElgamalGroupInput.md) | Accepted group identifier input for public ElGamal APIs. |
| [ElgamalKeyPair](type-aliases/ElgamalKeyPair.md) | Public and private key pair for a selected ElGamal suite. |
| [ElgamalParameters](type-aliases/ElgamalParameters.md) | Key material plus the resolved immutable group definition. |
| [GroupElement](type-aliases/GroupElement.md) | Generic finite-field group element marker. |
| [GroupName](type-aliases/GroupName.md) | Canonical names for the built-in RFC 7919 FFDHE suites. |
| [ParticipantIndex](type-aliases/ParticipantIndex.md) | One-based roster index used by higher-level committee logic. |
| [PrimeBits](type-aliases/PrimeBits.md) | Bit-size identifiers for the built-in RFC 7919 FFDHE suites. |
| [RandomBytesSource](type-aliases/RandomBytesSource.md) | Random byte source injected into sampling helpers for deterministic testing or custom runtime integration. |
| [ScalarQ](type-aliases/ScalarQ.md) | Scalar value intended to live in the prime-order field `Z_q`. |
| [SubgroupElement](type-aliases/SubgroupElement.md) | Element known to lie in the selected suite's prime-order subgroup. |
| [ValidatedPublicKey](type-aliases/ValidatedPublicKey.md) | Public key element that has already passed subgroup validation. |

## Functions

| Function | Description |
| ------ | ------ |
| [addEncryptedValues](functions/addEncryptedValues.md) | Adds two additive-mode ciphertexts component-wise. |
| [assertInSubgroup](functions/assertInSubgroup.md) | Validates that a value is a non-identity element of the prime-order subgroup. |
| [assertInSubgroupOrIdentity](functions/assertInSubgroupOrIdentity.md) | Validates that a value is either the subgroup identity or a non-identity subgroup element. |
| [assertPlaintextAdditive](functions/assertPlaintextAdditive.md) | Validates the plaintext domain and caller-supplied bound for additive ElGamal. |
| [assertScalarInZq](functions/assertScalarInZq.md) | Validates that a scalar belongs to `Z_q`. |
| [assertThreshold](functions/assertThreshold.md) | Validates a threshold `k` against a participant count `n`. |
| [assertValidAdditiveCiphertext](functions/assertValidAdditiveCiphertext.md) | Validates an additive ciphertext that may already be an aggregate. |
| [assertValidAdditivePlaintext](functions/assertValidAdditivePlaintext.md) | Validates the plaintext domain and caller-supplied bound for additive mode. |
| [assertValidAdditivePublicKey](functions/assertValidAdditivePublicKey.md) | Validates an additive-mode public key against the selected group. |
| [assertValidFreshAdditiveCiphertext](functions/assertValidFreshAdditiveCiphertext.md) | Validates a freshly produced additive ciphertext with subgroup `c1`. |
| [assertValidParticipantIndex](functions/assertValidParticipantIndex.md) | Validates a one-based participant index against a fixed roster size. |
| [assertValidPrivateKey](functions/assertValidPrivateKey.md) | Validates that a private key lies in the range `1..q-1`. |
| [assertValidPublicKey](functions/assertValidPublicKey.md) | Validates a public key as a non-identity prime-order subgroup element. |
| [babyStepGiantStep](functions/babyStepGiantStep.md) | Solves a bounded discrete logarithm with the baby-step giant-step method. |
| [bigintToFixedHex](functions/bigintToFixedHex.md) | Encodes a non-negative bigint as fixed-width lowercase hexadecimal. |
| [bytesToHex](functions/bytesToHex.md) | Encodes raw bytes as lowercase hexadecimal. |
| [concatBytes](functions/concatBytes.md) | Concatenates multiple byte arrays into a single contiguous buffer. |
| [decryptAdditive](functions/decryptAdditive.md) | Decrypts an additive ciphertext and recovers the bounded plaintext with baby-step giant-step. |
| [deriveH](functions/deriveH.md) | Derives the deterministic secondary subgroup generator `h` for a built-in suite. |
| [domainSeparator](functions/domainSeparator.md) | Encodes a domain-separation tag as UTF-8 bytes. |
| [encodeForChallenge](functions/encodeForChallenge.md) | Injectively encodes challenge transcript elements with 4-byte big-endian length prefixes. |
| [encryptAdditive](functions/encryptAdditive.md) | Encrypts an additive plaintext with fresh random `r in 1..q-1`. |
| [encryptAdditiveWithRandomness](functions/encryptAdditiveWithRandomness.md) | Encrypts an additive plaintext with caller-supplied randomness. |
| [fixedHexToBigint](functions/fixedHexToBigint.md) | Decodes a fixed-width hexadecimal string back into a bigint. |
| [generateParameters](functions/generateParameters.md) | Generates a fresh ElGamal key pair for a built-in group. |
| [generateParametersWithPrivateKey](functions/generateParametersWithPrivateKey.md) | Derives the public key for a caller-supplied private scalar. |
| [getGroup](functions/getGroup.md) | Returns one of the immutable built-in RFC 7919 group definitions. |
| [getWebCrypto](functions/getWebCrypto.md) | Returns the runtime Web Crypto implementation used by the library. |
| [hexToBytes](functions/hexToBytes.md) | Decodes a non-empty even-length hexadecimal string into bytes. |
| [hkdfSha256](functions/hkdfSha256.md) | Derives deterministic key material with HKDF-SHA-256. |
| [isInSubgroup](functions/isInSubgroup.md) | Returns `true` when the value is a non-identity element of the order-`q` subgroup. |
| [isInSubgroupOrIdentity](functions/isInSubgroupOrIdentity.md) | Returns `true` when the value is the subgroup identity or a valid subgroup element. |
| [listGroups](functions/listGroups.md) | Lists all immutable built-in RFC 7919 group definitions. |
| [mod](functions/mod.md) | Reduces a value into the canonical range `0..modulus-1`. |
| [modInvP](functions/modInvP.md) | Computes the multiplicative inverse of a value modulo `p`. |
| [modInvQ](functions/modInvQ.md) | Computes the multiplicative inverse of a value modulo `q`. |
| [modP](functions/modP.md) | Reduces a value into the range `0..p-1`. |
| [modPowP](functions/modPowP.md) | Computes `base^exponent mod p` for non-negative exponents. |
| [modQ](functions/modQ.md) | Reduces a value into the range `0..q-1`. |
| [randomBytes](functions/randomBytes.md) | Returns cryptographically secure random bytes. |
| [randomScalarBelow](functions/randomScalarBelow.md) | Samples a uniform scalar from the range `0..maxExclusive-1` with rejection sampling. |
| [randomScalarInRange](functions/randomScalarInRange.md) | Samples a uniform scalar from the range `minInclusive..maxExclusive-1`. |
| [sha256](functions/sha256.md) | Hashes bytes with SHA-256. |
| [utf8ToBytes](functions/utf8ToBytes.md) | Encodes a JavaScript string as UTF-8 bytes. |
