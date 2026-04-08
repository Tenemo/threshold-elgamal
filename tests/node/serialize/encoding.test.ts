import { describe, expect, it } from 'vitest';

import { InvalidPayloadError, InvalidScalarError } from '#core';
import {
    bigintToFixedHex,
    bytesToHex,
    concatBytes,
    domainSeparator,
    encodeForChallenge,
    fixedHexToBigint,
    hexToBytes,
} from '#serialize';

describe('foundational encoding', () => {
    it('round-trips fixed-width hex', () => {
        const hex = bigintToFixedHex(0x1234n, 4);

        expect(hex).toBe('00001234');
        expect(fixedHexToBigint(hex)).toBe(0x1234n);
    });

    it('rejects invalid fixed-width hex inputs', () => {
        expect(() => bigintToFixedHex(-1n, 4)).toThrow(InvalidScalarError);
        expect(() => bigintToFixedHex(0x123456789n, 4)).toThrow(
            InvalidScalarError,
        );
        expect(() => fixedHexToBigint('xyz')).toThrow(InvalidPayloadError);
        expect(() => fixedHexToBigint('123')).toThrow(InvalidPayloadError);
    });

    it('concatenates bytes deterministically', () => {
        const result = concatBytes(
            Uint8Array.from([1, 2]),
            Uint8Array.from([3, 4]),
            Uint8Array.from([5]),
        );

        expect(Array.from(result)).toEqual([1, 2, 3, 4, 5]);
    });

    it('encodes domain separators and challenge transcripts deterministically', () => {
        expect(bytesToHex(domainSeparator('proof'))).toBe('70726f6f66');
        expect(
            bytesToHex(
                encodeForChallenge('abc', 1n, Uint8Array.from([0x02, 0x03])),
            ),
        ).toBe('000000036162630000000101000000020203');
    });

    it('round-trips raw hex byte helpers', () => {
        const bytes = hexToBytes('00ff10');

        expect(Array.from(bytes)).toEqual([0, 255, 16]);
        expect(bytesToHex(bytes)).toBe('00ff10');
    });

    it('rejects invalid raw hex strings', () => {
        expect(() => hexToBytes('')).toThrow(InvalidPayloadError);
        expect(() => hexToBytes('0')).toThrow(InvalidPayloadError);
        expect(() => hexToBytes('zz')).toThrow(InvalidPayloadError);
    });
});
