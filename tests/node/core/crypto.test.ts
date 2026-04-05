import { describe, expect, it } from 'vitest';

import { hkdfSha256, sha256, utf8ToBytes } from 'threshold-elgamal/core';

describe('core crypto helpers', () => {
    it('hashes bytes with sha-256', async () => {
        const digest = await sha256(utf8ToBytes('threshold-elgamal'));

        expect(Buffer.from(digest).toString('hex')).toBe(
            '63fd47f6679886737e61652e6bbbf1a77d252f7df232d30c9c708863afa4e782',
        );
    });

    it('derives deterministic HKDF output', async () => {
        const okm = await hkdfSha256(
            utf8ToBytes('ikm'),
            utf8ToBytes('salt'),
            utf8ToBytes('info'),
            32,
        );

        expect(Buffer.from(okm).toString('hex')).toBe(
            'fe8f9615d2374c0d17f77d1aeaf408c2e75fe0466073d0def23c733e2f862dfd',
        );
    });
});
