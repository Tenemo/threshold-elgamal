/** Progress callback payload for chunked runtime helpers. */
export type RuntimeProgress = {
    readonly completed: number;
    readonly total: number;
};

/** Options shared by chunked runtime helpers. */
export type ChunkedRuntimeOptions = {
    /** Maximum items processed before yielding back to the event loop. */
    readonly chunkSize?: number;
    /** Optional progress callback invoked after each processed chunk. */
    readonly onProgress?: (progress: RuntimeProgress) => void;
};

const normalizeChunkSize = (chunkSize: number | undefined): number => {
    if (chunkSize === undefined) {
        return 32;
    }

    if (!Number.isInteger(chunkSize) || chunkSize < 1) {
        throw new Error('chunkSize must be a positive integer');
    }

    return chunkSize;
};

/**
 * Yields back to the event loop to keep long-running browser work responsive.
 *
 * @returns Promise resolved on the next macrotask turn.
 */
export const yieldToEventLoop = async (): Promise<void> =>
    new Promise((resolve) => {
        globalThis.setTimeout(resolve, 0);
    });

/**
 * Applies an async worker to every item in order while yielding between
 * chunks.
 *
 * @param items Ordered input items.
 * @param worker Async worker applied to each item.
 * @param options Chunking and progress options.
 * @returns Ordered worker results.
 */
export const mapChunked = async <TItem, TResult>(
    items: readonly TItem[],
    worker: (
        item: TItem,
        index: number,
        items: readonly TItem[],
    ) => Promise<TResult>,
    options: ChunkedRuntimeOptions = {},
): Promise<readonly TResult[]> => {
    const chunkSize = normalizeChunkSize(options.chunkSize);
    const results: TResult[] = [];

    for (let start = 0; start < items.length; start += chunkSize) {
        const end = Math.min(start + chunkSize, items.length);
        for (let index = start; index < end; index += 1) {
            results.push(await worker(items[index], index, items));
        }

        options.onProgress?.({
            completed: end,
            total: items.length,
        });

        if (end < items.length) {
            await yieldToEventLoop();
        }
    }

    return results;
};

/**
 * Executes an async side-effect worker for every item in order while yielding
 * between chunks.
 *
 * @param items Ordered input items.
 * @param worker Async worker applied to each item.
 * @param options Chunking and progress options.
 */
export const forEachChunked = async <TItem>(
    items: readonly TItem[],
    worker: (
        item: TItem,
        index: number,
        items: readonly TItem[],
    ) => Promise<void>,
    options: ChunkedRuntimeOptions = {},
): Promise<void> => {
    await mapChunked(
        items,
        async (item, index, collection) => {
            await worker(item, index, collection);
            return undefined;
        },
        options,
    );
};
