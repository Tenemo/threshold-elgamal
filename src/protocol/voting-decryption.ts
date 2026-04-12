import {
    InvalidPayloadError,
    RISTRETTO_GROUP,
    assertInSubgroupOrIdentity,
} from '../core/index';
import { deriveTranscriptVerificationKey } from '../dkg/verification';
import { verifyDLEQProof, type DLEQStatement } from '../proofs/dleq';
import type { DecryptionShare } from '../threshold/index';

import { auditSignedPayloads } from './board-audit';
import type {
    DecryptionSharePayload,
    SignedPayload,
    VerifiedDecryptionSharePayload,
    VerifiedOptionDecryptionShares,
    VerifyDecryptionSharePayloadsByOptionInput,
} from './types';
import { decodeCompactProof } from './voting-codecs';
import {
    assertNonEmptyString,
    assertPhase,
    assertValidOptionIndex,
    buildOptionAggregateMap,
    buildVotingManifestContext,
    decryptionProofContext,
    DECRYPTION_SHARE_PHASE,
} from './voting-shared';

const verifyAuditedDecryptionSharePayloadsByOption = async (input: {
    readonly aggregates: VerifyDecryptionSharePayloadsByOptionInput['aggregates'];
    readonly context: Awaited<ReturnType<typeof buildVotingManifestContext>>;
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly dkg: VerifyDecryptionSharePayloadsByOptionInput['dkg'];
}): Promise<readonly VerifiedOptionDecryptionShares[]> => {
    const qualifiedParticipantSet = new Set(
        input.dkg.qualifiedParticipantIndices,
    );
    const aggregateMap = buildOptionAggregateMap(
        input.aggregates,
        input.context.optionCount,
    );
    const payloadsByOption = new Map<
        number,
        SignedPayload<DecryptionSharePayload>[]
    >();

    for (
        let optionIndex = 1;
        optionIndex <= input.context.optionCount;
        optionIndex += 1
    ) {
        payloadsByOption.set(optionIndex, []);
    }

    for (const signedPayload of input.decryptionSharePayloads) {
        const payload = signedPayload.payload;
        assertPhase(payload, DECRYPTION_SHARE_PHASE, 'Decryption share');
        assertValidOptionIndex(
            payload.optionIndex,
            input.context.optionCount,
            'Decryption share',
        );
        payloadsByOption.get(payload.optionIndex)?.push(signedPayload);
    }

    const verifiedShares: VerifiedOptionDecryptionShares[] = [];
    for (
        let optionIndex = 1;
        optionIndex <= input.context.optionCount;
        optionIndex += 1
    ) {
        const optionAggregate = aggregateMap.get(optionIndex);
        const optionPayloads = payloadsByOption.get(optionIndex) ?? [];

        if (optionAggregate === undefined) {
            throw new InvalidPayloadError(
                `Missing verified aggregate for option ${optionIndex}`,
            );
        }
        if (optionPayloads.length < input.dkg.threshold) {
            throw new InvalidPayloadError(
                `At least ${input.dkg.threshold} decryption shares are required for option ${optionIndex}`,
            );
        }

        const seenParticipants = new Set<number>();
        const optionVerifiedShares: VerifiedDecryptionSharePayload[] = [];
        for (const signedPayload of optionPayloads) {
            const payload = signedPayload.payload;
            if (payload.sessionId !== input.context.sessionId) {
                throw new InvalidPayloadError(
                    'Decryption-share payload session does not match the verification input',
                );
            }
            if (payload.manifestHash !== input.context.manifestHash) {
                throw new InvalidPayloadError(
                    'Decryption-share payload manifest hash does not match the verification input',
                );
            }
            if (!qualifiedParticipantSet.has(payload.participantIndex)) {
                throw new InvalidPayloadError(
                    `Decryption share came from non-qualified participant ${payload.participantIndex}`,
                );
            }
            if (seenParticipants.has(payload.participantIndex)) {
                throw new InvalidPayloadError(
                    `Duplicate decryption share for participant ${payload.participantIndex} and option ${optionIndex} is not allowed`,
                );
            }
            seenParticipants.add(payload.participantIndex);

            assertNonEmptyString(
                payload.transcriptHash,
                'Decryption transcript hash',
            );
            if (
                payload.transcriptHash !==
                optionAggregate.aggregate.transcriptHash
            ) {
                throw new InvalidPayloadError(
                    `Decryption share transcript hash mismatch for participant ${payload.participantIndex} and option ${optionIndex}`,
                );
            }
            if (payload.ballotCount !== optionAggregate.aggregate.ballotCount) {
                throw new InvalidPayloadError(
                    `Decryption share ballot count mismatch for participant ${payload.participantIndex} and option ${optionIndex}`,
                );
            }

            assertInSubgroupOrIdentity(payload.decryptionShare);
            const decryptionShare = {
                index: payload.participantIndex,
                value: payload.decryptionShare,
            } satisfies DecryptionShare;
            const statement: DLEQStatement = {
                publicKey: deriveTranscriptVerificationKey(
                    input.dkg.feldmanCommitments,
                    payload.participantIndex,
                    RISTRETTO_GROUP,
                ),
                ciphertext: optionAggregate.aggregate.ciphertext,
                decryptionShare: decryptionShare.value,
            };
            const proof = decodeCompactProof(payload.proof);
            const valid = await verifyDLEQProof(
                proof,
                statement,
                RISTRETTO_GROUP,
                decryptionProofContext(payload, input.context.protocolVersion),
            );

            if (!valid) {
                throw new InvalidPayloadError(
                    `Decryption-share proof failed verification for participant ${payload.participantIndex} and option ${optionIndex}`,
                );
            }

            optionVerifiedShares.push({
                payload: signedPayload,
                share: decryptionShare,
            });
        }

        verifiedShares.push({
            optionIndex,
            decryptionShares: optionVerifiedShares,
        });
    }

    return verifiedShares;
};

/**
 * Verifies typed decryption-share payloads against the DKG transcript-derived
 * trustee keys and one locally recomputed aggregate ciphertext per option slot.
 *
 * Signatures are expected to have been checked already against the frozen
 * registration roster.
 *
 * @param input Typed decryption-share verification input.
 * @returns Verified decryption shares grouped by option.
 */
export const verifyDecryptionSharePayloadsByOption = async (
    input: VerifyDecryptionSharePayloadsByOptionInput,
): Promise<readonly VerifiedOptionDecryptionShares[]> => {
    const context = await buildVotingManifestContext(
        input.manifest,
        input.sessionId,
    );
    const auditedShares = await auditSignedPayloads(
        input.decryptionSharePayloads,
    );

    return verifyAuditedDecryptionSharePayloadsByOption({
        aggregates: input.aggregates,
        context,
        decryptionSharePayloads: auditedShares.acceptedPayloads,
        dkg: input.dkg,
    });
};
