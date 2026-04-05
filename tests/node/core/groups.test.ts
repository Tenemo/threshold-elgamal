import { describe, expect, it } from 'vitest';

import {
    deriveH,
    getGroup,
    listGroups,
    modPowP,
    UnsupportedSuiteError,
} from 'threshold-elgamal/core';

describe('core groups', () => {
    it('returns q as (p - 1) / 2 for every supported group', () => {
        for (const group of listGroups()) {
            expect(group.q).toBe((group.p - 1n) / 2n);
        }
    });

    it('returns a deterministic second generator in the subgroup', () => {
        for (const group of listGroups()) {
            expect(group.h).not.toBe(group.g);
            expect(group.h > 1n).toBe(true);
            expect(modPowP(group.h, group.q, group.p)).toBe(1n);
        }
    });

    it('derives h deterministically from the frozen suite inputs', async () => {
        for (const group of listGroups()) {
            await expect(deriveH(group)).resolves.toBe(group.h);
        }
    });

    it('supports lookup by bits and by name', () => {
        expect(getGroup(2048)).toEqual(getGroup('ffdhe2048'));
        expect(getGroup(3072)).toEqual(getGroup('ffdhe3072'));
        expect(getGroup(4096)).toEqual(getGroup('ffdhe4096'));
    });

    it('rejects unsupported groups', () => {
        expect(() => getGroup(1024 as never)).toThrow(UnsupportedSuiteError);
    });
});
