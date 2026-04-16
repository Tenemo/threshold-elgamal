import { describe, expect, it } from 'vitest';

import {
    canonicalizeElectionManifest,
    createElectionManifest,
    majorityThreshold,
    scoreRangeDomain,
    type ElectionManifest,
} from '#root';

describe('public manifest', () => {
    it.each([
        {
            name: 'zero-based range',
            scoreRange: { min: 0, max: 5 },
            canonical:
                '{"optionList":["Alpha","Beta"],"rosterHash":"roster-hash","scoreRange":{"max":5,"min":0}}',
        },
        {
            name: 'non-zero minimum range',
            scoreRange: { min: 1, max: 5 },
            canonical:
                '{"optionList":["Alpha","Beta"],"rosterHash":"roster-hash","scoreRange":{"max":5,"min":1}}',
        },
        {
            name: 'legacy score width with explicit range',
            scoreRange: { min: 1, max: 10 },
            canonical:
                '{"optionList":["Alpha","Beta"],"rosterHash":"roster-hash","scoreRange":{"max":10,"min":1}}',
        },
    ])('creates the explicit shipped manifest shape for $name', (entry) => {
        const manifest = createElectionManifest({
            rosterHash: 'roster-hash',
            optionList: ['Alpha', 'Beta'],
            scoreRange: entry.scoreRange,
        });

        expect(manifest).toEqual({
            rosterHash: 'roster-hash',
            optionList: ['Alpha', 'Beta'],
            scoreRange: entry.scoreRange,
        });
        expect(canonicalizeElectionManifest(manifest)).toBe(entry.canonical);
    });

    it('rejects removed manifest fields from the public API', () => {
        const legacyFields = [
            'participantCount',
            'reconstructionThreshold',
            'minimumPublishedVoterCount',
            'protocolVersion',
            'ballotCompletenessPolicy',
            'ballotFinality',
            'scoreDomain',
            'epochDeadlines',
        ] as const;

        for (const legacyField of legacyFields) {
            expect(() =>
                createElectionManifest({
                    rosterHash: 'roster-hash',
                    optionList: ['Alpha', 'Beta'],
                    scoreRange: { min: 1, max: 10 },
                    [legacyField]:
                        legacyField === 'epochDeadlines'
                            ? ['2026-04-11T12:00:00Z']
                            : 1,
                } as unknown as ElectionManifest),
            ).toThrow(
                `Legacy manifest field "${legacyField}" is not supported by the public manifest`,
            );
        }
    });

    it('rejects manifests without an explicit score range', () => {
        expect(() =>
            createElectionManifest({
                rosterHash: 'roster-hash',
                optionList: ['Alpha', 'Beta'],
            } as unknown as ElectionManifest),
        ).toThrow('Election manifest requires an explicit scoreRange');
    });

    it('expands explicit score ranges into the public ballot-proof domain', () => {
        expect(scoreRangeDomain({ min: 0, max: 5 })).toEqual([
            0n,
            1n,
            2n,
            3n,
            4n,
            5n,
        ]);
        expect(scoreRangeDomain({ min: 3, max: 3 })).toEqual([3n]);
    });

    it.each([
        {
            name: 'negative minimum',
            scoreRange: { min: -1, max: 5 },
            message: 'Election manifest scoreRange.min must be non-negative',
        },
        {
            name: 'negative maximum',
            scoreRange: { min: 0, max: -1 },
            message: 'Election manifest scoreRange.max must be non-negative',
        },
        {
            name: 'inverted range',
            scoreRange: { min: 5, max: 4 },
            message:
                'Election manifest scoreRange.min must not exceed scoreRange.max',
        },
        {
            name: 'non-integer minimum',
            scoreRange: { min: 1.5, max: 5 },
            message: 'Election manifest scoreRange.min must be a safe integer',
        },
        {
            name: 'non-integer maximum',
            scoreRange: { min: 1, max: 5.5 },
            message: 'Election manifest scoreRange.max must be a safe integer',
        },
    ])('rejects invalid score ranges for $name', (entry) => {
        expect(() =>
            createElectionManifest({
                rosterHash: 'roster-hash',
                optionList: ['Alpha', 'Beta'],
                scoreRange: entry.scoreRange,
            }),
        ).toThrow(entry.message);

        expect(() => scoreRangeDomain(entry.scoreRange)).toThrow();
    });

    it('derives the shipped honest-majority threshold for odd and even rosters', () => {
        expect(majorityThreshold(3)).toBe(2);
        expect(majorityThreshold(10)).toBe(5);
        expect(majorityThreshold(11)).toBe(6);
    });
});
