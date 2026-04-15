import { describe, expect, it } from 'vitest';

import { hkdfSha256, InvalidScalarError, utf8ToBytes } from '#core';

describe('core crypto helpers', () => {
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
