# Library invariants

These invariants apply to every v2 module and public API.

- All scalar arithmetic is performed in `Z_q`, never `Z_p`.
- All secret-dependent group operations use validated prime-order subgroup elements only.
- All externally supplied public inputs are validated before secret-dependent use.
- All signed protocol payloads are serialized canonically before hashing or signing.
- All Fiat-Shamir challenges use strong statement binding and include session and suite context.
- All cryptographic inputs and outputs use `bigint`, never JavaScript `number`.
- All randomness comes from a cryptographically secure RNG with rejection sampling where range reduction is required.
- Multiplicative mode rejects plaintext `0` and all negative values.
- Additive mode accepts plaintext `0` but still rejects negative values.
