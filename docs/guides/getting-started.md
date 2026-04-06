# Getting started

Use the safe root package. The current library surface is centered on additive ElGamal.

## Install

```bash
pnpm add threshold-elgamal
```

## Safe additive round-trip

```typescript
import {
    decryptAdditive,
    encryptAdditive,
    generateParameters,
    getGroup,
} from 'threshold-elgamal';

const group = 'ffdhe3072' as const;
const suite = getGroup(group);
const { publicKey, privateKey } = generateParameters(group);

const ciphertext = encryptAdditive(7n, publicKey, group, 20n);
const plaintext = decryptAdditive(ciphertext, privateKey, group, 20n);

console.log(plaintext); // 7n
console.log(suite.securityEstimate); // 125
```

## Rules to keep in mind

- Always pass an explicit group identifier. There is no implicit default suite.
- Always use `bigint`, never JavaScript `number`, for cryptographic values.
- Keep additive plaintexts within `0..bound`, and keep `bound < q`.
- Reuse the same group across key generation, encryption, combination, and decryption.

## Where to go next

- For tallying sums, read [Additive ElGamal](additive-elgamal.html).
- For exact signatures and types, use the [API reference](../api/index.html).
