[**threshold-elgamal**](../index.md)

***

[threshold-elgamal](../modules.md) / core

# core

Low-level finite-field helpers, randomness, suite definitions, validation,
and exported error classes.

This module is safe to consume directly, but it assumes the caller already
understands which higher-level ElGamal mode they intend to build on top.

## Classes

| Class | Description |
| ------ | ------ |
| [IndexOutOfRangeError](classes/IndexOutOfRangeError.md) | Raised when a participant index falls outside the valid `1..n` range. |
| [InvalidGroupElementError](classes/InvalidGroupElementError.md) | Raised when a group element is not valid for the selected finite-field suite. |
| [InvalidPayloadError](classes/InvalidPayloadError.md) | Raised when serialized payload bytes do not satisfy the required encoding. |
| [InvalidProofError](classes/InvalidProofError.md) | Raised when a proof transcript or response fails verification. |
| [InvalidScalarError](classes/InvalidScalarError.md) | Raised when a scalar value falls outside the expected mathematical domain. |
| [InvalidShareError](classes/InvalidShareError.md) | Raised when a serialized or reconstructed share fails validation. |
| [PhaseViolationError](classes/PhaseViolationError.md) | Raised when a protocol phase transition violates the state machine rules. |
| [PlaintextDomainError](classes/PlaintextDomainError.md) | Raised when a plaintext lies outside the allowed domain for the chosen mode. |
| [ThresholdViolationError](classes/ThresholdViolationError.md) | Raised when threshold parameters do not satisfy `1 <= k <= n`. |
| [TranscriptMismatchError](classes/TranscriptMismatchError.md) | Raised when transcript hashes or canonical bytes do not match expectations. |
| [UnsupportedSuiteError](classes/UnsupportedSuiteError.md) | Raised when the requested suite or runtime capability is unavailable. |

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [Brand](type-aliases/Brand.md) | Nominal typing helper used to distinguish compatible runtime values in the type system. |
| [CryptoGroup](type-aliases/CryptoGroup.md) | Immutable built-in group definition exposed by `getGroup()` and keygen APIs. |
| [GroupElement](type-aliases/GroupElement.md) | Generic finite-field group element marker. |
| [GroupName](type-aliases/GroupName.md) | Canonical names for the built-in RFC 7919 FFDHE suites. |
| [PrimeBits](type-aliases/PrimeBits.md) | Bit-size identifiers for the built-in RFC 7919 FFDHE suites. |
| [RandomBytesSource](type-aliases/RandomBytesSource.md) | Random byte source injected into sampling helpers for deterministic testing or custom runtime integration. |
| [ScalarQ](type-aliases/ScalarQ.md) | Scalar value intended to live in the prime-order field `Z_q`. |
| [SubgroupElement](type-aliases/SubgroupElement.md) | Element known to lie in the selected suite's prime-order subgroup. |
| [ValidatedPublicKey](type-aliases/ValidatedPublicKey.md) | Public key element that has already passed subgroup validation. |

## Functions

| Function | Description |
| ------ | ------ |
| [assertInSubgroup](functions/assertInSubgroup.md) | Validates that a value is a non-identity element of the prime-order subgroup. |
| [assertInSubgroupOrIdentity](functions/assertInSubgroupOrIdentity.md) | Validates that a value is either the subgroup identity or a non-identity subgroup element. |
| [assertPlaintextAdditive](functions/assertPlaintextAdditive.md) | Validates the plaintext domain and caller-supplied bound for additive ElGamal. |
| [assertScalarInZq](functions/assertScalarInZq.md) | Validates that a scalar belongs to `Z_q`. |
| [assertThreshold](functions/assertThreshold.md) | Validates threshold parameters for `k`-of-`n` protocols. |
| [assertValidParticipantIndex](functions/assertValidParticipantIndex.md) | Validates a 1-based participant index for a fixed participant count. |
| [assertValidPublicKey](functions/assertValidPublicKey.md) | Validates a public key as a non-identity prime-order subgroup element. |
| [deriveH](functions/deriveH.md) | Recomputes the deterministic secondary generator `h` for a built-in suite. |
| [getGroup](functions/getGroup.md) | Returns one of the immutable built-in RFC 7919 group definitions. |
| [getWebCrypto](functions/getWebCrypto.md) | Returns the runtime Web Crypto implementation used by the library. |
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
