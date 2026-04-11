import { describe, expect, it } from 'vitest';

import {
    canonicalizeElectionManifest,
    defaultMinimumPublishedVoterCount,
    deriveSessionId,
    validateElectionManifest,
    type ElectionManifest,
} from '#protocol';
const baseManifest = (): ElectionManifest => ({
    protocolVersion: 'v1',
    reconstructionThreshold: 3,
    participantCount: 5,
    minimumPublishedVoterCount: 4,
    ballotCompletenessPolicy: 'ALL_OPTIONS_REQUIRED',
    ballotFinality: 'first-valid',
    scoreDomain: '1..10',
    rosterHash: 'roster-hash',
    optionList: ['Alpha', 'Beta'],
    epochDeadlines: ['2026-04-08T12:00:00Z', '2026-04-08T13:00:00Z'],
});
describe('manifest validation', () => {
    it('accepts supported distributed score-voting manifests', () => {
        const manifest = baseManifest();
        expect(validateElectionManifest(manifest)).toBe(manifest);
        expect(canonicalizeElectionManifest(manifest)).toBe(
            '{"ballotCompletenessPolicy":"ALL_OPTIONS_REQUIRED","ballotFinality":"first-valid","epochDeadlines":["2026-04-08T12:00:00Z","2026-04-08T13:00:00Z"],"minimumPublishedVoterCount":4,"optionList":["Alpha","Beta"],"participantCount":5,"protocolVersion":"v1","reconstructionThreshold":3,"rosterHash":"roster-hash","scoreDomain":"1..10"}',
        );
    });
    it('rejects distributed manifests with fewer than three participants', () => {
        const manifest = {
            ...baseManifest(),
            participantCount: 2,
            reconstructionThreshold: 2,
            minimumPublishedVoterCount: 2,
        };
        expect(() => validateElectionManifest(manifest)).toThrow(
            'Distributed threshold workflows require at least three participants',
        );
    });
    it('accepts organizer-selected distributed thresholds including n-of-n', () => {
        const cases = [
            {
                participantCount: 3,
                reconstructionThreshold: 3,
                minimumPublishedVoterCount: 3,
            },
            {
                participantCount: 4,
                reconstructionThreshold: 2,
                minimumPublishedVoterCount: 3,
            },
            {
                participantCount: 4,
                reconstructionThreshold: 4,
                minimumPublishedVoterCount: 4,
            },
            {
                participantCount: 5,
                reconstructionThreshold: 5,
                minimumPublishedVoterCount: 5,
            },
        ] as const;

        for (const testCase of cases) {
            const manifest = {
                ...baseManifest(),
                ...testCase,
            };

            expect(validateElectionManifest(manifest)).toBe(manifest);
        }
    });
    it('rejects thresholds outside the generic distributed range', () => {
        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                reconstructionThreshold: 0,
            }),
        ).toThrow('Threshold 0 must satisfy 1 <= k <= n (n = 5)');
        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                reconstructionThreshold: 6,
            }),
        ).toThrow('Threshold 6 must satisfy 1 <= k <= n (n = 5)');
    });
    it('rejects invalid manifest policy, option, and deadline invariants', () => {
        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                ballotFinality:
                    'last-valid' as ElectionManifest['ballotFinality'],
            }),
        ).toThrow('Only "first-valid" ballot finality is supported');
        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                ballotCompletenessPolicy:
                    'OPTIONAL' as ElectionManifest['ballotCompletenessPolicy'],
            }),
        ).toThrow(
            'Only "ALL_OPTIONS_REQUIRED" ballot completeness is supported',
        );
        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                scoreDomain: '0..10' as ElectionManifest['scoreDomain'],
            }),
        ).toThrow('Only the fixed "1..10" score domain is supported');
        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                optionList: ['Alpha', 'Alpha'],
            }),
        ).toThrow('Duplicate option "Alpha" is not allowed');
        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                epochDeadlines: [
                    '2026-04-08T13:00:00Z',
                    '2026-04-08T12:00:00Z',
                ],
            }),
        ).toThrow('Epoch deadlines must be strictly increasing');
    });
    it('rejects publication floors below the shipped privacy minimum', () => {
        expect(defaultMinimumPublishedVoterCount(3, 5)).toBe(4);
        expect(defaultMinimumPublishedVoterCount(5, 5)).toBe(5);
        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                minimumPublishedVoterCount: 3,
            }),
        ).toThrow('Minimum published voter count must be an integer in 4..5');
    });
    it('rejects legacy manifest fields explicitly', () => {
        const legacyThreshold = {
            ...baseManifest(),
            threshold: 3,
        } as unknown as ElectionManifest;
        const legacyFloor = {
            ...baseManifest(),
            minimumPublicationThreshold: 4,
        } as unknown as ElectionManifest;
        const legacyAbstention = {
            ...baseManifest(),
            allowAbstention: false,
        } as unknown as ElectionManifest;
        expect(() => validateElectionManifest(legacyThreshold)).toThrow(
            'Legacy manifest field "threshold" is not supported on the Ristretto beta line',
        );
        expect(() => validateElectionManifest(legacyFloor)).toThrow(
            'Legacy manifest field "minimumPublicationThreshold" is not supported on the Ristretto beta line',
        );
        expect(() => validateElectionManifest(legacyAbstention)).toThrow(
            'Legacy manifest field "allowAbstention" is not supported on the Ristretto beta line',
        );
    });
    it('derives session identifiers injectively', async () => {
        const ambiguousLeft = await deriveSessionId(
            'manifest-hash',
            'roster-hash',
            'nonce:a',
            'timestamp',
        );
        const ambiguousRight = await deriveSessionId(
            'manifest-hash',
            'roster-hash',
            'nonce',
            'a:timestamp',
        );
        expect(ambiguousLeft).toHaveLength(64);
        expect(ambiguousRight).toHaveLength(64);
        expect(ambiguousLeft).not.toBe(ambiguousRight);
    });
});
