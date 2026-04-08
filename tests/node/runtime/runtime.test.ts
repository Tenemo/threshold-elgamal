import { describe, expect, it } from 'vitest';

import { forEachChunked, mapChunked, yieldToEventLoop } from '#runtime';

describe('runtime helpers', () => {
    it('maps chunked work in order and reports chunk progress', async () => {
        const progress: number[] = [];
        const seenItems: number[] = [];

        const results = await mapChunked(
            [1, 2, 3, 4, 5],
            async (item) => {
                await Promise.resolve();
                seenItems.push(item);
                return item * 2;
            },
            {
                chunkSize: 2,
                onProgress: ({ completed, total }) => {
                    progress.push(completed * 100 + total);
                },
            },
        );

        expect(seenItems).toEqual([1, 2, 3, 4, 5]);
        expect(results).toEqual([2, 4, 6, 8, 10]);
        expect(progress).toEqual([205, 405, 505]);
    });

    it('executes chunked side effects and allows explicit event-loop yielding', async () => {
        const visited: string[] = [];

        await yieldToEventLoop();
        await forEachChunked(
            ['a', 'b', 'c'],
            async (item, index) => {
                await Promise.resolve();
                visited.push(`${index}:${item}`);
            },
            {
                chunkSize: 1,
            },
        );

        expect(visited).toEqual(['0:a', '1:b', '2:c']);
    });

    it('rejects invalid chunk sizes', async () => {
        await expect(
            mapChunked(
                [1],
                async (item) => {
                    await Promise.resolve();
                    return item;
                },
                {
                    chunkSize: 0,
                },
            ),
        ).rejects.toThrow('chunkSize must be a positive integer');
    });
});
