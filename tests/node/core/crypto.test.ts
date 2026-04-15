import { describe, expect, it } from 'vitest';

import { hkdfSha256, InvalidScalarError, sha256, utf8ToBytes } from '#core';

describe('core crypto helpers', () => {
    it('hashes bytes deterministically and preserves the digest length', async () => {
        const input = utf8ToBytes('threshold-elgamal');
        const sameInput = utf8ToBytes('threshold-elgamal');
        const differentInput = utf8ToBytes('threshold-elgamal-alt');
        const digest = await sha256(input);
        const sameDigest = await sha256(sameInput);
        const differentDigest = await sha256(differentInput);

        expect(digest).toHaveLength(32);
        expect(digest).toEqual(sameDigest);
        expect(digest).not.toEqual(differentDigest);
    });

    it('derives deterministic HKDF output with the requested length', async () => {
        const okm = await hkdfSha256(
            utf8ToBytes('ikm'),
            utf8ToBytes('salt'),
            utf8ToBytes('info'),
            32,
        );
        const sameOkm = await hkdfSha256(
            utf8ToBytes('ikm'),
            utf8ToBytes('salt'),
            utf8ToBytes('info'),
            32,
        );
        const differentInfoOkm = await hkdfSha256(
            utf8ToBytes('ikm'),
            utf8ToBytes('salt'),
            utf8ToBytes('other-info'),
            32,
        );

        expect(okm).toHaveLength(32);
        expect(okm).toEqual(sameOkm);
        expect(okm).not.toEqual(differentInfoOkm);
    });

    it('rejects invalid HKDF output lengths', async () => {
        await expect(
            hkdfSha256(
                utf8ToBytes('ikm'),
                utf8ToBytes('salt'),
                utf8ToBytes('info'),
                -1,
            ),
        ).rejects.toThrow(InvalidScalarError);
        await expect(
            hkdfSha256(
                utf8ToBytes('ikm'),
                utf8ToBytes('salt'),
                utf8ToBytes('info'),
                1.5,
            ),
        ).rejects.toThrow(InvalidScalarError);
    });
});
