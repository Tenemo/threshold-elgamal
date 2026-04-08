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
        const source = createSequenceSource([0xff], [0x04]);

        expect(randomScalarBelow(6n, source)).toBe(4n);
    });

    it('returns zero immediately for a unit upper bound', () => {
        const source = vi.fn<RandomBytesSource>(() => {
            throw new Error('Unit upper bounds should not consume randomness');
        });

        expect(randomScalarBelow(1n, source)).toBe(0n);
        expect(source).not.toHaveBeenCalled();
    });

    it('handles byte-aligned mask cases without zeroing the leading byte', () => {
        expect(randomScalarBelow(128n, createSequenceSource([0x7f]))).toBe(
            127n,
        );
        expect(randomScalarBelow(256n, createSequenceSource([0xff]))).toBe(
            255n,
        );
        expect(
            randomScalarBelow(65536n, createSequenceSource([0xff, 0xff])),
        ).toBe(65535n);
    });

    it('handles awkward non-byte-aligned rejection sampling bounds', () => {
        expect(
            randomScalarBelow(
                257n,
                createSequenceSource([0xff, 0xff], [0x01, 0x00]),
            ),
        ).toBe(256n);
        expect(randomScalarBelow(7n, createSequenceSource([0x06]))).toBe(6n);
        expect(
            randomScalarBelow(3n, createSequenceSource([0xff], [0x02])),
        ).toBe(2n);
    });

    it('does not mutate buffers returned by injected random sources', () => {
        const sharedBuffer = Uint8Array.from([0xff]);
        const source: RandomBytesSource = (length) => {
            expect(length).toBe(1);
            return sharedBuffer;
        };

        expect(randomScalarBelow(128n, source)).toBe(127n);
        expect(Array.from(sharedBuffer)).toEqual([0xff]);
    });

    it('can reach every output value for small bounds', () => {
        let next = 0;
        const source: RandomBytesSource = (length) => {
            const bytes = new Uint8Array(length);
            for (let index = 0; index < length; index += 1) {
                bytes[index] = next & 0xff;
                next = (next + 1) & 0xff;
            }

            return bytes;
        };
        const seen = new Set<bigint>();

        for (let index = 0; index < 10000; index += 1) {
            seen.add(randomScalarBelow(10n, source));
        }

        expect(seen).toEqual(new Set([0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n]));
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
