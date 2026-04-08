import { describe, expect, it, vi } from 'vitest';

import {
    InvalidScalarError,
    randomBytes,
    randomScalarBelow,
    randomScalarInRange,
    type RandomBytesSource,
} from '#core';

const createSequenceSource = (...chunks: number[][]): RandomBytesSource => {
    let index = 0;

    return (length: number): Uint8Array => {
        const chunk = chunks[index];
        index += 1;

        if (chunk === undefined) {
            throw new Error('Sequence source exhausted');
        }

        if (chunk.length !== length) {
            throw new Error(
                `Sequence source expected length ${length}, got ${chunk.length}`,
            );
        }

        return Uint8Array.from(chunk);
    };
};

describe('core randomness', () => {
    it('returns the requested number of random bytes', () => {
        const bytes = randomBytes(32);

        expect(bytes).toBeInstanceOf(Uint8Array);
        expect(bytes).toHaveLength(32);
    });

    it('supports large secure random byte requests without quota errors', () => {
        const bytes = randomBytes(200000);

        expect(bytes).toBeInstanceOf(Uint8Array);
        expect(bytes).toHaveLength(200000);
    });

    it('rejects invalid random byte lengths', () => {
        expect(() => randomBytes(-1)).toThrow(InvalidScalarError);
        expect(() => randomBytes(1.5)).toThrow(InvalidScalarError);
    });

    it('rejects random sources that return the wrong byte length', () => {
        expect(() => randomBytes(4, () => new Uint8Array([1, 2, 3]))).toThrow(
            InvalidScalarError,
        );
    });

    it('fills large default random byte requests in Web Crypto sized chunks', () => {
        const calls: number[] = [];
        const originalCrypto = globalThis.crypto;

        vi.stubGlobal('crypto', {
            subtle: originalCrypto.subtle,
            getRandomValues: (typedArray: Uint8Array): Uint8Array => {
                calls.push(typedArray.byteLength);
                typedArray.fill(0xab);
                return typedArray;
            },
        });

        try {
            const bytes = randomBytes(200000);

            expect(bytes).toHaveLength(200000);
            expect(calls).toEqual([65536, 65536, 65536, 3392]);
            expect(bytes[0]).toBe(0xab);
            expect(bytes[199999]).toBe(0xab);
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it('does not chunk injected random sources', () => {
        const calls: number[] = [];
        const source: RandomBytesSource = (length) => {
            calls.push(length);
            return new Uint8Array(length);
        };

        const bytes = randomBytes(200000, source);

        expect(bytes).toHaveLength(200000);
        expect(calls).toEqual([200000]);
    });

    it('uses rejection sampling for randomScalarBelow', () => {
        const source = createSequenceSource([9], [4]);

        expect(randomScalarBelow(6n, source)).toBe(4n);
    });

    it('samples randomScalarInRange with min inclusive and max exclusive semantics', () => {
        const source = createSequenceSource([2]);

        expect(randomScalarInRange(10n, 16n, source)).toBe(12n);
    });

    it('rejects invalid bounds', () => {
        expect(() => randomScalarBelow(0n)).toThrow(InvalidScalarError);
        expect(() => randomScalarInRange(5n, 5n)).toThrow(InvalidScalarError);
        expect(() => randomScalarInRange(6n, 5n)).toThrow(InvalidScalarError);
    });
});
