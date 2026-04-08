# Getting started

Use the safe root package. The current library surface is centered on additive ElGamal.

## Install

```bash
pnpm add threshold-elgamal
```

## Runtime prerequisites

- Use ESM `import` syntax. The published package does not expose CommonJS `require()` entry points.
- Browsers need native `bigint` together with Web Crypto (`crypto.subtle` and `crypto.getRandomValues`).
- Node needs version `24.14.1` or newer with `globalThis.crypto`.

## Safe additive round-trip

```typescript
import {
    decryptAdditive,
    encryptAdditive,
    generateParameters,
    getGroup,
} from "threshold-elgamal";

const group = "ffdhe3072" as const;
const suite = getGroup(group);
const { publicKey, privateKey } = generateParameters(group);
const messageBound = 10n;
const tallyBound = 20n;

const ciphertext = encryptAdditive(7n, publicKey, group, messageBound);
const plaintext = decryptAdditive(ciphertext, privateKey, group, tallyBound);

console.log(plaintext); // 7n
console.log(suite.securityEstimate); // 125
```

## Planning bounds

- Use the encryption-time bound for the maximum single plaintext you allow.
- Use the decryption-time bound for the maximum plaintext you expect to recover.
- Those values can differ. The library validates the encryption-time bound against the input plaintext, but it does not store that bound in the ciphertext.
- Larger decryption bounds make additive recovery slower and more memory-hungry because baby-step giant-step work grows roughly with `sqrt(bound)`.

For example, if every ballot is in `0..10` and a final tally combines `50` ballots, encrypt each ballot with `10n` and decrypt the final sum with `500n`.

## Rules to keep in mind

- Always pass an explicit group identifier. There is no implicit default suite.
- Always use `bigint`, never JavaScript `number`, for cryptographic values.
- Keep additive plaintexts within `0..bound`, and keep `bound < q`.
- Reuse the same group across key generation, encryption, combination, and decryption.

## Where to go next

- For tallying sums, read [Additive ElGamal](additive-elgamal.html).
- For exact signatures and types, use the [API reference](../api/index.html).
