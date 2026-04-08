import { describe, expect, it } from 'vitest';

import plainElgamalVectors from '../../../test-vectors/plain-elgamal.json';

import {
    deriveH,
    getGroup,
    listGroups,
    modPowP,
    UnsupportedSuiteError,
} from '#core';

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

    it('matches the frozen h vectors for every shipped group', () => {
        for (const [groupName, vector] of Object.entries(
            plainElgamalVectors.groups,
        )) {
            expect(getGroup(groupName as never).h).toBe(BigInt(vector.h));
        }
    });

    it('recomputes the deterministic h values from the public derivation', async () => {
        for (const group of listGroups()) {
            await expect(deriveH(group.name)).resolves.toBe(group.h);
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

    it('returns frozen built-in group objects', () => {
        const group = getGroup(2048);

        expect(Object.isFrozen(group)).toBe(true);
        expect(() => {
            (group as { p: bigint }).p = 17n;
        }).toThrow(TypeError);
        expect(getGroup(2048).p).not.toBe(17n);
    });
});
