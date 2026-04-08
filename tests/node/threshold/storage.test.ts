import { describe, expect, it } from 'vitest';

import {
    generateShareWrappingKey,
    isShareStorageSupported,
    unwrapShareFromStorage,
    wrapShareForStorage,
} from '#threshold';

describe('share storage helpers', () => {
    it('wraps and unwraps Shamir shares for local storage', async () => {
        const key = await generateShareWrappingKey();
        const record = await wrapShareForStorage(
            { index: 3, value: 12345n },
            key,
            32,
        );

        await expect(unwrapShareFromStorage(record, key)).resolves.toEqual({
            index: 3,
            value: 12345n,
        });
    });

    it('reports storage support based on IndexedDB availability', () => {
        expect(typeof isShareStorageSupported()).toBe('boolean');
    });
});
