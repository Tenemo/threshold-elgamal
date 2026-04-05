# Library invariants

These invariants apply to the current v2 modules and public API.

- All scalar arithmetic is performed in `Z_q`, never `Z_p`.
- All secret-dependent group operations use validated prime-order subgroup elements only.
- All externally supplied public inputs are validated before secret-dependent use.
- All public group selection resolves only to built-in RFC 7919 suites.
- All built-in group objects are frozen before exposure.
- All cryptographic inputs and outputs use `bigint`, never JavaScript `number`.
- All randomness comes from a cryptographically secure RNG with rejection sampling where range reduction is required.
- Multiplicative mode rejects plaintext `0` and all negative values.
- Additive mode accepts plaintext `0` but still rejects negative values.
- Additive encryption requires an explicit plaintext bound below `q`.
- Aggregate ciphertext validation allows subgroup identity only where ciphertext algebra permits it.
