import { describe, expect, it } from 'vitest';

import {
    InvalidScalarError,
    randomBytes,
    randomScalarBelow,
    randomScalarInRange,
    type RandomBytesSource,
} from '../../../src/core';

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

    it('rejects invalid random byte lengths', () => {
        expect(() => randomBytes(-1)).toThrow(InvalidScalarError);
        expect(() => randomBytes(1.5)).toThrow(InvalidScalarError);
    });

    it('rejects random sources that return the wrong byte length', () => {
        expect(() => randomBytes(4, () => new Uint8Array([1, 2, 3]))).toThrow(
            InvalidScalarError,
        );
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
