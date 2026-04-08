import { describe, expect, it } from 'vitest';

import { IndexOutOfRangeError } from '#core';
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

    it('rejects invalid participant indices in wrapped share records', async () => {
        const key = await generateShareWrappingKey();

        await expect(
            wrapShareForStorage({ index: 0, value: 12345n }, key, 32),
        ).rejects.toBeInstanceOf(IndexOutOfRangeError);
        await expect(
            unwrapShareFromStorage(
                {
                    index: 0,
                    iv: '000000000000000000000000',
                    ciphertext: '00',
                },
                key,
            ),
        ).rejects.toBeInstanceOf(IndexOutOfRangeError);
    });

    it('authenticates the stored share index', async () => {
        const key = await generateShareWrappingKey();
        const record = await wrapShareForStorage(
            { index: 3, value: 12345n },
            key,
            32,
        );

        await expect(
            unwrapShareFromStorage(
                {
                    ...record,
                    index: 4,
                },
                key,
            ),
        ).rejects.toThrow();
    });

    it('reports storage support based on IndexedDB availability', () => {
        expect(typeof isShareStorageSupported()).toBe('boolean');
    });
});
