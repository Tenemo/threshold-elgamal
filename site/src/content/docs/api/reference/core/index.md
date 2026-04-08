---
title: "core"
description: "Generated reference page for the `core` export surface."
editUrl: false
sidebar:
  order: 2
---
[**threshold-elgamal**](../)

***

[threshold-elgamal](../modules/) / core

# core

Low-level finite-field helpers, randomness, suite definitions, validation,
and exported error classes.

This module is safe to consume directly, but it assumes the caller already
understands which higher-level ElGamal mode they intend to build on top.

## Classes

| Class | Description |
| ------ | ------ |
| [IndexOutOfRangeError](classes/IndexOutOfRangeError/) | Raised when a participant index falls outside the valid `1..n` range. |
| [InvalidGroupElementError](classes/InvalidGroupElementError/) | Raised when a group element is not valid for the selected finite-field suite. |
| [InvalidPayloadError](classes/InvalidPayloadError/) | Raised when serialized payload bytes do not satisfy the required encoding. |
| [InvalidProofError](classes/InvalidProofError/) | Raised when a proof transcript or response fails verification. |
| [InvalidScalarError](classes/InvalidScalarError/) | Raised when a scalar value falls outside the expected mathematical domain. |
| [InvalidShareError](classes/InvalidShareError/) | Raised when a serialized or reconstructed share fails validation. |
| [PhaseViolationError](classes/PhaseViolationError/) | Raised when a protocol step transition violates the state machine rules. |
| [PlaintextDomainError](classes/PlaintextDomainError/) | Raised when a plaintext lies outside the allowed domain for the chosen mode. |
| [ThresholdViolationError](classes/ThresholdViolationError/) | Raised when threshold parameters do not satisfy `1 <= k <= n`. |
| [TranscriptMismatchError](classes/TranscriptMismatchError/) | Raised when transcript hashes or canonical bytes do not match expectations. |
| [UnsupportedSuiteError](classes/UnsupportedSuiteError/) | Raised when the requested suite or runtime capability is unavailable. |

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [Brand](type-aliases/Brand/) | Nominal typing helper used to distinguish compatible runtime values in the type system. |
| [CryptoGroup](type-aliases/CryptoGroup/) | Immutable built-in group definition exposed by `getGroup()` and keygen APIs. |
| [GroupElement](type-aliases/GroupElement/) | Generic finite-field group element marker. |
| [GroupName](type-aliases/GroupName/) | Canonical names for the built-in RFC 7919 FFDHE suites. |
| [PrimeBits](type-aliases/PrimeBits/) | Bit-size identifiers for the built-in RFC 7919 FFDHE suites. |
| [RandomBytesSource](type-aliases/RandomBytesSource/) | Random byte source injected into sampling helpers for deterministic testing or custom runtime integration. |
| [ScalarQ](type-aliases/ScalarQ/) | Scalar value intended to live in the prime-order field `Z_q`. |
| [SubgroupElement](type-aliases/SubgroupElement/) | Element known to lie in the selected suite's prime-order subgroup. |
| [ValidatedPublicKey](type-aliases/ValidatedPublicKey/) | Public key element that has already passed subgroup validation. |

## Functions

| Function | Description |
| ------ | ------ |
| [assertInSubgroup](functions/assertInSubgroup/) | Validates that a value is a non-identity element of the prime-order subgroup. |
| [assertInSubgroupOrIdentity](functions/assertInSubgroupOrIdentity/) | Validates that a value is either the subgroup identity or a non-identity subgroup element. |
| [assertMajorityThreshold](functions/assertMajorityThreshold/) | Validates that the supplied threshold matches the supported honest-majority threshold `ceil(n / 2)`. |
| [assertPlaintextAdditive](functions/assertPlaintextAdditive/) | Validates the plaintext domain and caller-supplied bound for additive ElGamal. |
| [assertPositiveParticipantIndex](functions/assertPositiveParticipantIndex/) | Validates a 1-based participant index without assuming a fixed participant count. |
| [assertScalarInZq](functions/assertScalarInZq/) | Validates that a scalar belongs to `Z_q`. |
| [assertThreshold](functions/assertThreshold/) | Validates threshold parameters for `k`-of-`n` protocols. |
| [assertValidParticipantIndex](functions/assertValidParticipantIndex/) | Validates a 1-based participant index for a fixed participant count. |
| [assertValidPublicKey](functions/assertValidPublicKey/) | Validates a public key as a non-identity prime-order subgroup element. |
| [deriveH](functions/deriveH/) | Recomputes the deterministic secondary generator `h` for a built-in suite. |
| [getGroup](functions/getGroup/) | Returns one of the immutable built-in RFC 7919 group definitions. |
| [getWebCrypto](functions/getWebCrypto/) | Returns the runtime Web Crypto implementation used by the library. |
| [hkdfSha256](functions/hkdfSha256/) | Derives deterministic key material with HKDF-SHA-256. |
| [isInSubgroup](functions/isInSubgroup/) | Returns `true` when the value is a non-identity element of the order-`q` subgroup. |
| [isInSubgroupOrIdentity](functions/isInSubgroupOrIdentity/) | Returns `true` when the value is the subgroup identity or a valid subgroup element. |
| [listGroups](functions/listGroups/) | Lists all immutable built-in RFC 7919 group definitions. |
| [majorityThreshold](functions/majorityThreshold/) | Derives the supported honest-majority threshold `ceil(n / 2)`. |
| [mod](functions/mod/) | Reduces a value into the canonical range `0..modulus-1`. |
| [modInvP](functions/modInvP/) | Computes the multiplicative inverse of a value modulo `p`. |
| [modInvQ](functions/modInvQ/) | Computes the multiplicative inverse of a value modulo `q`. |
| [modP](functions/modP/) | Reduces a value into the range `0..p-1`. |
| [modPowP](functions/modPowP/) | Computes `base^exponent mod p` for non-negative exponents. |
| [modQ](functions/modQ/) | Reduces a value into the range `0..q-1`. |
| [randomBytes](functions/randomBytes/) | Returns cryptographically secure random bytes. |
| [randomScalarBelow](functions/randomScalarBelow/) | Samples a uniform scalar from the range `0..maxExclusive-1` with rejection sampling. |
| [randomScalarInRange](functions/randomScalarInRange/) | Samples a uniform scalar from the range `minInclusive..maxExclusive-1`. |
| [sha256](functions/sha256/) | Hashes bytes with SHA-256. |
| [utf8ToBytes](functions/utf8ToBytes/) | Encodes a JavaScript string as UTF-8 bytes. |
