import { describe, expect, it } from 'vitest';

import {
    canonicalizeElectionManifest,
    defaultMinimumPublicationThreshold,
    deriveSessionId,
    validateElectionManifest,
    type ElectionManifest,
} from '#protocol';

const baseManifest = (): ElectionManifest => ({
    protocolVersion: 'v1',
    suiteId: 'ffdhe3072',
    threshold: 3,
    participantCount: 5,
    minimumPublicationThreshold: 4,
    allowAbstention: false,
    scoreDomainMin: 1,
    scoreDomainMax: 10,
    ballotFinality: 'first-valid',
    rosterHash: 'roster-hash',
    optionList: ['Alpha', 'Beta'],
    epochDeadlines: ['2026-04-08T12:00:00Z', '2026-04-08T13:00:00Z'],
});

describe('manifest validation', () => {
    it('accepts supported honest-majority score-voting manifests', () => {
        const manifest = baseManifest();

        expect(validateElectionManifest(manifest)).toBe(manifest);
        expect(canonicalizeElectionManifest(manifest)).toBe(
            '{"allowAbstention":false,"ballotFinality":"first-valid","epochDeadlines":["2026-04-08T12:00:00Z","2026-04-08T13:00:00Z"],"minimumPublicationThreshold":4,"optionList":["Alpha","Beta"],"participantCount":5,"protocolVersion":"v1","rosterHash":"roster-hash","scoreDomainMax":10,"scoreDomainMin":1,"suiteId":"ffdhe3072","threshold":3}',
        );
    });

    it('rejects thresholds outside the supported honest-majority policy', () => {
        const manifest = {
            ...baseManifest(),
            threshold: 4,
        };

        expect(() => validateElectionManifest(manifest)).toThrow(
            'Supported distributed threshold must equal ceil(n / 2) = 3 for n = 5',
        );
    });

    it('rejects invalid score, finality, option, and deadline invariants', () => {
        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                allowAbstention: true,
                scoreDomainMin: 1,
            }),
        ).toThrow('Allowing abstention requires scoreDomainMin = 0');

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
        expect(defaultMinimumPublicationThreshold(3, 5)).toBe(4);

        expect(() =>
            validateElectionManifest({
                ...baseManifest(),
                minimumPublicationThreshold: 3,
            }),
        ).toThrow('Minimum publication threshold must be an integer in 4..5');
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
