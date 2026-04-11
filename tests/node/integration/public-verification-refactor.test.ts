import { beforeAll, describe, expect, it } from 'vitest';

import { verifyDKGTranscriptFromAuditedTranscript } from '../../../src/dkg/verification.js';
import { auditSignedPayloads } from '../../../src/protocol/board-audit.js';
import { verifyBallotSubmissionPayloadsByOptionFromAuditedPayloads } from '../../../src/protocol/voting-ballots.js';
import {
    verifyDecryptionSharePayloadsByOption,
    verifyDecryptionSharePayloadsByOptionFromAuditedPayloads,
} from '../../../src/protocol/voting-decryption.js';
import { buildVotingManifestContext } from '../../../src/protocol/voting-shared.js';
import { runVotingFlowScenario } from '../../../tools/internal/voting-flow-harness.js';

import {
    createBallotSubmissionPayload,
    createDecryptionSharePayload,
    verifyBallotSubmissionPayloadsByOption,
    verifyDKGTranscript,
    verifyElectionCeremonyDetailed,
} from '#root';

const fixtureTimeoutMs = 240_000;

type VotingFlowFixture = Awaited<ReturnType<typeof runVotingFlowScenario>>;

const replaceByParticipantAndOption = <
    TPayload extends {
        readonly payload: {
            readonly optionIndex: number;
            readonly participantIndex: number;
        };
    },
>(
    payloads: readonly TPayload[],
    participantIndex: number,
    optionIndex: number,
    replacement: TPayload,
): readonly TPayload[] =>
    payloads.map((payload) =>
        payload.payload.participantIndex === participantIndex &&
        payload.payload.optionIndex === optionIndex
            ? replacement
            : payload,
    );

describe('public verification refactor parity', () => {
    let fixture: VotingFlowFixture;

    beforeAll(async () => {
        fixture = await runVotingFlowScenario({
            participantCount: 4,
            optionList: ['One', 'Two', 'Three'],
            participantVotes: [
                [1n, 2n, 3n],
                [4n, 5n, 6n],
                [7n, 8n, 9n],
                [10n, 1n, 2n],
            ],
        });
    }, fixtureTimeoutMs);

    it(
        'matches audited and public DKG verification outputs',
        async () => {
            const auditedTranscript = await auditSignedPayloads(
                fixture.dkgTranscript,
            );

            await expect(
                verifyDKGTranscript({
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                    transcript: fixture.dkgTranscript,
                }),
            ).resolves.toEqual(
                await verifyDKGTranscriptFromAuditedTranscript({
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                    transcript: auditedTranscript.acceptedPayloads,
                }),
            );
        },
        fixtureTimeoutMs,
    );

    it(
        'matches audited and public ballot verification outputs',
        async () => {
            const context = await buildVotingManifestContext(
                fixture.manifest,
                fixture.sessionId,
            );
            const auditedBallots = await auditSignedPayloads(
                fixture.ballotPayloads,
            );

            await expect(
                verifyBallotSubmissionPayloadsByOption({
                    ballotPayloads: fixture.ballotPayloads,
                    publicKey: fixture.verified.dkg.derivedPublicKey,
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                }),
            ).resolves.toEqual(
                await verifyBallotSubmissionPayloadsByOptionFromAuditedPayloads(
                    {
                        ballotPayloads: auditedBallots.acceptedPayloads,
                        context,
                        publicKey: fixture.verified.dkg.derivedPublicKey,
                    },
                ),
            );
        },
        fixtureTimeoutMs,
    );

    it(
        'matches audited and public decryption-share verification outputs',
        async () => {
            const context = await buildVotingManifestContext(
                fixture.manifest,
                fixture.sessionId,
            );
            const auditedShares = await auditSignedPayloads(
                fixture.decryptionSharePayloads,
            );

            await expect(
                verifyDecryptionSharePayloadsByOption({
                    aggregates: fixture.verified.options.map((option) => ({
                        optionIndex: option.optionIndex,
                        aggregate: option.ballots.aggregate,
                    })),
                    dkg: fixture.verified.dkg,
                    decryptionSharePayloads: fixture.decryptionSharePayloads,
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                }),
            ).resolves.toEqual(
                await verifyDecryptionSharePayloadsByOptionFromAuditedPayloads({
                    aggregates: fixture.verified.options.map((option) => ({
                        optionIndex: option.optionIndex,
                        aggregate: option.ballots.aggregate,
                    })),
                    context,
                    decryptionSharePayloads: auditedShares.acceptedPayloads,
                    dkg: fixture.verified.dkg,
                }),
            );
        },
        fixtureTimeoutMs,
    );

    it(
        'preserves ballot-stage failure messages across audited and public entrypoints',
        async () => {
            const context = await buildVotingManifestContext(
                fixture.manifest,
                fixture.sessionId,
            );
            const tamperedBallot = await createBallotSubmissionPayload(
                fixture.participants[0].auth.privateKey,
                {
                    ...fixture.ballotPayloads[0].payload,
                    sessionId: 'replayed-session',
                },
            );
            const tamperedBallots = replaceByParticipantAndOption(
                fixture.ballotPayloads,
                1,
                1,
                tamperedBallot,
            );
            const auditedBallots = await auditSignedPayloads(tamperedBallots);
            const expectedMessage =
                'Ballot submission payload session does not match the verification input';

            await expect(
                verifyBallotSubmissionPayloadsByOption({
                    ballotPayloads: tamperedBallots,
                    publicKey: fixture.verified.dkg.derivedPublicKey,
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                }),
            ).rejects.toThrow(expectedMessage);
            await expect(
                verifyBallotSubmissionPayloadsByOptionFromAuditedPayloads({
                    ballotPayloads: auditedBallots.acceptedPayloads,
                    context,
                    publicKey: fixture.verified.dkg.derivedPublicKey,
                }),
            ).rejects.toThrow(expectedMessage);
        },
        fixtureTimeoutMs,
    );

    it(
        'preserves decryption-stage failure messages across audited and public entrypoints',
        async () => {
            const context = await buildVotingManifestContext(
                fixture.manifest,
                fixture.sessionId,
            );
            const tamperedShare = await createDecryptionSharePayload(
                fixture.participants[0].auth.privateKey,
                {
                    ...fixture.decryptionSharePayloads[0].payload,
                    transcriptHash: 'aa'.repeat(32),
                },
            );
            const tamperedShares = replaceByParticipantAndOption(
                fixture.decryptionSharePayloads,
                1,
                1,
                tamperedShare,
            );
            const auditedShares = await auditSignedPayloads(tamperedShares);
            const expectedMessage =
                'Decryption share transcript hash mismatch for participant 1 and option 1';
            const aggregates = fixture.verified.options.map((option) => ({
                optionIndex: option.optionIndex,
                aggregate: option.ballots.aggregate,
            }));

            await expect(
                verifyDecryptionSharePayloadsByOption({
                    aggregates,
                    dkg: fixture.verified.dkg,
                    decryptionSharePayloads: tamperedShares,
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                }),
            ).rejects.toThrow(expectedMessage);
            await expect(
                verifyDecryptionSharePayloadsByOptionFromAuditedPayloads({
                    aggregates,
                    context,
                    decryptionSharePayloads: auditedShares.acceptedPayloads,
                    dkg: fixture.verified.dkg,
                }),
            ).rejects.toThrow(expectedMessage);
        },
        fixtureTimeoutMs,
    );

    it(
        'requires key-derivation confirmations by default but accepts explicit legacy replays',
        async () => {
            const transcriptWithoutConfirmations = fixture.dkgTranscript.filter(
                (entry) =>
                    entry.payload.messageType !== 'key-derivation-confirmation',
            );

            await expect(
                verifyDKGTranscript({
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                    transcript: transcriptWithoutConfirmations,
                }),
            ).rejects.toThrow(
                'Expected at least 4 key-derivation confirmations, received 0',
            );
            await expect(
                verifyElectionCeremonyDetailed({
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                    dkgTranscript: transcriptWithoutConfirmations,
                    ballotPayloads: fixture.ballotPayloads,
                    ballotClosePayload: fixture.ballotClosePayload,
                    decryptionSharePayloads: fixture.decryptionSharePayloads,
                    tallyPublications: fixture.tallyPublications,
                }),
            ).rejects.toThrow(
                'Expected at least 4 key-derivation confirmations, received 0',
            );

            await expect(
                verifyDKGTranscript({
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                    transcript: transcriptWithoutConfirmations,
                    keyDerivationConfirmationPolicy: 'optional',
                }),
            ).resolves.toEqual(
                expect.objectContaining({
                    derivedPublicKey: fixture.verified.dkg.derivedPublicKey,
                    qual: fixture.verified.dkg.qual,
                }),
            );
            await expect(
                verifyElectionCeremonyDetailed({
                    manifest: fixture.manifest,
                    sessionId: fixture.sessionId,
                    dkgTranscript: transcriptWithoutConfirmations,
                    keyDerivationConfirmationPolicy: 'optional',
                    ballotPayloads: fixture.ballotPayloads,
                    ballotClosePayload: fixture.ballotClosePayload,
                    decryptionSharePayloads: fixture.decryptionSharePayloads,
                    tallyPublications: fixture.tallyPublications,
                }),
            ).resolves.toEqual(
                expect.objectContaining({
                    perOptionTallies: fixture.verified.perOptionTallies,
                    qual: fixture.verified.qual,
                }),
            );
        },
        fixtureTimeoutMs,
    );
});
