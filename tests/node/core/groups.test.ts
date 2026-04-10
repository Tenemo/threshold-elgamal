import { describe, expect, it } from 'vitest';

import { encodePoint, RISTRETTO_ZERO } from '../../../src/core/ristretto.js';

import { deriveH, getGroup, listGroups, UnsupportedSuiteError } from '#core';

describe('core groups', () => {
    it('exposes the shipped ristretto255 group definition', () => {
        const groups = listGroups();

        expect(groups).toHaveLength(1);
        expect(groups[0]).toMatchObject({
            name: 'ristretto255',
            byteLength: 32,
            scalarByteLength: 32,
            securityEstimate: 128,
        });
        expect(groups[0].q).toBeGreaterThan(0n);
    });

    it('returns a deterministic secondary generator that differs from the base point', () => {
        const group = getGroup('ristretto255');

        expect(group.h).not.toBe(group.g);
        expect(group.h).not.toBe(encodePoint(RISTRETTO_ZERO));
    });

    it('recomputes the deterministic h value from the public derivation', () => {
        for (const group of listGroups()) {
            expect(deriveH(group.name)).toBe(group.h);
        }
    });

    it('accepts beta helper aliases for legacy finite-field identifiers', () => {
        expect(getGroup(2048)).toEqual(getGroup('ristretto255'));
        expect(getGroup('ffdhe2048')).toEqual(getGroup('ristretto255'));
        expect(getGroup(3072)).toEqual(getGroup('ristretto255'));
        expect(getGroup('ffdhe3072')).toEqual(getGroup('ristretto255'));
        expect(getGroup(4096)).toEqual(getGroup('ristretto255'));
        expect(getGroup('ffdhe4096')).toEqual(getGroup('ristretto255'));
    });

    it('rejects unsupported groups', () => {
        expect(() => getGroup(1024 as never)).toThrow(UnsupportedSuiteError);
        expect(() => getGroup('unknown-suite' as never)).toThrow(
            UnsupportedSuiteError,
        );
    });

    it('returns frozen built-in group objects', () => {
        const group = getGroup('ristretto255');

        expect(Object.isFrozen(group)).toBe(true);
        expect(() => {
            (group as { q: bigint }).q = 17n;
        }).toThrow(TypeError);
        expect(getGroup('ristretto255').q).not.toBe(17n);
    });
});
