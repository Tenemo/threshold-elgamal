[**threshold-elgamal**](../index.md)

***

[threshold-elgamal](../modules.md) / threshold

# threshold

Dealer-generated threshold sharing, combination, and wrapped-share storage
helpers.

This module contains the current shipped threshold decryption surface for
additive ElGamal.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [DecryptionShare](type-aliases/DecryptionShare.md) | A participant's partial decryption contribution. |
| [Polynomial](type-aliases/Polynomial.md) | Coefficients for `f(x) = a0 + a1*x + ... + a{k-1}*x^{k-1}` over `Z_q`. |
| [Share](type-aliases/Share.md) | A single indexed Shamir share over `Z_q`. |
| [ThresholdKeySet](type-aliases/ThresholdKeySet.md) | Complete dealer-produced threshold key material. |
| [VerifiedAggregateCiphertext](type-aliases/VerifiedAggregateCiphertext.md) | A threshold aggregate tied to a verified additive ciphertext. |
| [WrappedShareRecord](type-aliases/WrappedShareRecord.md) | Wrapped share record suitable for durable local storage. |

## Functions

| Function | Description |
| ------ | ------ |
| [combineDecryptionShares](functions/combineDecryptionShares.md) | Combines indexed decryption shares via Lagrange interpolation at `x = 0`. |
| [createDecryptionShare](functions/createDecryptionShare.md) | Creates a partial decryption share `d_i = c1^{x_i} mod p`. |
| [createVerifiedDecryptionShare](functions/createVerifiedDecryptionShare.md) | Creates a decryption share only for a locally recomputed aggregate that is anchored to a canonical transcript hash. |
| [dealerKeyGen](functions/dealerKeyGen.md) | Splits a fresh secret into indexed Shamir shares and derives the threshold public key for dealer-based threshold decryption. |
| [deriveSharesFromPolynomial](functions/deriveSharesFromPolynomial.md) | Deterministically derives indexed shares from a caller-supplied polynomial. |
| [evaluatePolynomial](functions/evaluatePolynomial.md) | Evaluates a polynomial at `x` with Horner's method over `Z_q`. |
| [generatePolynomial](functions/generatePolynomial.md) | Generates a random degree-`threshold - 1` polynomial over `Z_q`. |
| [generateShareWrappingKey](functions/generateShareWrappingKey.md) | Generates a non-extractable AES-GCM key for share wrapping. |
| [isShareStorageSupported](functions/isShareStorageSupported.md) | Returns whether the current runtime exposes the minimum capabilities required for wrapped-share storage. |
| [lagrangeCoefficient](functions/lagrangeCoefficient.md) | Computes the Lagrange coefficient for `participantIndex` at `x = 0`. |
| [unwrapShareFromStorage](functions/unwrapShareFromStorage.md) | Restores a wrapped Shamir share value from local storage. |
| [wrapShareForStorage](functions/wrapShareForStorage.md) | Wraps a Shamir share value for durable local storage. |
