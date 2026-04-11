import { describe, expect, it } from 'vitest';

import {
    canonicalizeElectionManifest,
    createElectionManifest,
    majorityThreshold,
    type ElectionManifest,
} from '#root';

describe('public manifest', () => {
    it('creates the minimal shipped manifest shape', () => {
        const manifest = createElectionManifest({
            rosterHash: 'roster-hash',
            optionList: ['Alpha', 'Beta'],
        });

        expect(manifest).toEqual({
            rosterHash: 'roster-hash',
            optionList: ['Alpha', 'Beta'],
        });
        expect(canonicalizeElectionManifest(manifest)).toBe(
            '{"optionList":["Alpha","Beta"],"rosterHash":"roster-hash"}',
        );
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
                    [legacyField]:
                        legacyField === 'epochDeadlines'
                            ? ['2026-04-11T12:00:00Z']
                            : 1,
                } as unknown as ElectionManifest),
            ).toThrow(
                `Legacy manifest field "${legacyField}" is not supported on the Ristretto beta line`,
            );
        }
    });

    it('derives the shipped honest-majority threshold for odd and even rosters', () => {
        expect(majorityThreshold(3)).toBe(2);
        expect(majorityThreshold(10)).toBe(5);
        expect(majorityThreshold(11)).toBe(6);
    });
});
