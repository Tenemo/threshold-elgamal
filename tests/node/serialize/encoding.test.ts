import { describe, expect, it } from 'vitest';

import { InvalidPayloadError, InvalidScalarError } from '#core';
import {
    bigintToFixedHex,
    bigintToFixedBytes,
    bytesToHex,
    concatBytes,
    domainSeparator,
    encodeForChallenge,
    encodeSequenceForChallenge,
    fixedHexToBigInt,
    hexToBytes,
} from '#serialize';
import {
    bytesToHex as coreBytesToHex,
    hexToBytes as coreHexToBytes,
} from '#src/core/bytes';

describe('foundational encoding', () => {
    it('round-trips fixed-width hex', () => {
        const hex = bigintToFixedHex(0x1234n, 4);

        expect(hex).toBe('00001234');
        expect(fixedHexToBigInt(hex)).toBe(0x1234n);
        expect(Array.from(bigintToFixedBytes(0x1234n, 4))).toEqual([
            0x00, 0x00, 0x12, 0x34,
        ]);
    });

    it('rejects invalid fixed-width hex inputs', () => {
        expect(() => bigintToFixedHex(-1n, 4)).toThrow(InvalidScalarError);
        expect(() => bigintToFixedHex(0x123456789n, 4)).toThrow(
            InvalidScalarError,
        );
        expect(() => fixedHexToBigInt('xyz')).toThrow(InvalidPayloadError);
        expect(() => fixedHexToBigInt('123')).toThrow(InvalidPayloadError);
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

    it('count-prefixes variable-length transcript sequences', () => {
        const left = encodeSequenceForChallenge([
            Uint8Array.from([0x12]),
            Uint8Array.from([0x34, 0x56]),
        ]);
        const right = encodeSequenceForChallenge([
            Uint8Array.from([0x12, 0x34]),
            Uint8Array.from([0x56]),
        ]);

        expect(bytesToHex(left)).toBe('000000020000000112000000023456');
        expect(bytesToHex(left)).not.toBe(bytesToHex(right));
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

    it('keeps core and serialize hex helpers behaviorally aligned', () => {
        const mixedCaseHex = '00Aa10';
        const serializedBytes = hexToBytes(mixedCaseHex);
        const coreBytes = coreHexToBytes(mixedCaseHex);

        expect(Array.from(serializedBytes)).toEqual(Array.from(coreBytes));
        expect(bytesToHex(serializedBytes)).toBe('00aa10');
        expect(coreBytesToHex(coreBytes)).toBe('00aa10');

        for (const decode of [hexToBytes, coreHexToBytes]) {
            expect(() => decode('xyz')).toThrow(InvalidPayloadError);
            expect(() => decode('xyz')).toThrow(
                'Hex input must be a non-empty even-length hexadecimal string',
            );
        }
    });
});
