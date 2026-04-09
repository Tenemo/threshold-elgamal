import { InvalidPayloadError } from '../core/index.js';
import { deriveTranscriptVerificationKey } from '../dkg/verification.js';
import { verifyDLEQProof, type DLEQStatement } from '../proofs/dleq.js';
import { fixedHexToBigint } from '../serialize/index.js';
import type { DecryptionShare } from '../threshold/index.js';

import type { DecryptionSharePayload, SignedPayload } from './types.js';
import { decodeCompactProof } from './voting-codecs.js';
import {
    assertNonEmptyString,
    assertPhase,
    assertSingleOptionManifest,
    assertValidOptionIndex,
    buildOptionAggregateMap,
    buildVotingManifestContext,
    decryptionProofContext,
    DECRYPTION_SHARE_PHASE,
} from './voting-shared.js';
import type {
    OptionAggregateInput,
    VerifiedDecryptionSharePayload,
    VerifiedOptionDecryptionShares,
    VerifyDecryptionSharePayloadsByOptionInput,
    VerifyDecryptionSharePayloadsInput,
} from './voting-types.js';

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
    const qualSet = new Set(input.dkg.qual);
    const aggregateMap = buildOptionAggregateMap(
        input.aggregates,
        context.optionCount,
    );
    const payloadsByOption = new Map<
        number,
        SignedPayload<DecryptionSharePayload>[]
    >();

    for (
        let optionIndex = 1;
        optionIndex <= context.optionCount;
        optionIndex += 1
    ) {
        payloadsByOption.set(optionIndex, []);
    }

    for (const signedPayload of input.decryptionSharePayloads) {
        const payload = signedPayload.payload;
        assertPhase(payload, DECRYPTION_SHARE_PHASE, 'Decryption share');
        assertValidOptionIndex(
            payload.optionIndex,
            context.optionCount,
            'Decryption share',
        );
        payloadsByOption.get(payload.optionIndex)?.push(signedPayload);
    }

    const verifiedShares: VerifiedOptionDecryptionShares[] = [];
    for (
        let optionIndex = 1;
        optionIndex <= context.optionCount;
        optionIndex += 1
    ) {
        const optionAggregate = aggregateMap.get(optionIndex);
        const optionPayloads = payloadsByOption.get(optionIndex) ?? [];

        if (optionAggregate === undefined) {
            throw new InvalidPayloadError(
                `Missing verified aggregate for option ${optionIndex}`,
            );
        }
        if (optionPayloads.length < context.manifest.threshold) {
            throw new InvalidPayloadError(
                `At least ${context.manifest.threshold} decryption shares are required for option ${optionIndex}`,
            );
        }

        const seenParticipants = new Set<number>();
        const optionVerifiedShares: VerifiedDecryptionSharePayload[] = [];
        for (const signedPayload of optionPayloads) {
            const payload = signedPayload.payload;
            if (payload.sessionId !== context.sessionId) {
                throw new InvalidPayloadError(
                    'Decryption-share payload session does not match the verification input',
                );
            }
            if (payload.manifestHash !== context.manifestHash) {
                throw new InvalidPayloadError(
                    'Decryption-share payload manifest hash does not match the verification input',
                );
            }
            if (!qualSet.has(payload.participantIndex)) {
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

            const decryptionShare = {
                index: payload.participantIndex,
                value: fixedHexToBigint(payload.decryptionShare),
            } satisfies DecryptionShare;
            const statement: DLEQStatement = {
                publicKey: deriveTranscriptVerificationKey(
                    input.dkg.feldmanCommitments,
                    payload.participantIndex,
                    input.dkg.group,
                ),
                ciphertext: optionAggregate.aggregate.ciphertext,
                decryptionShare: decryptionShare.value,
            };
            const proof = decodeCompactProof(payload.proof);
            const valid = await verifyDLEQProof(
                proof,
                statement,
                input.dkg.group,
                decryptionProofContext(payload, input.dkg.group),
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
 * trustee keys and one locally recomputed aggregate ciphertext for a
 * single-option manifest.
 *
 * @param input Typed decryption-share verification input.
 * @returns Verified decryption shares ready for threshold recombination.
 */
export const verifyDecryptionSharePayloads = async (
    input: VerifyDecryptionSharePayloadsInput,
): Promise<readonly VerifiedDecryptionSharePayload[]> => {
    const context = await buildVotingManifestContext(
        input.manifest,
        input.sessionId,
    );
    assertSingleOptionManifest(
        context.manifest,
        'verifyDecryptionSharePayloads',
    );

    const verifiedShares = await verifyDecryptionSharePayloadsByOption({
        aggregates: [
            {
                optionIndex: 1,
                aggregate: input.aggregate,
            },
        ] satisfies readonly OptionAggregateInput[],
        dkg: input.dkg,
        decryptionSharePayloads: input.decryptionSharePayloads,
        manifest: context.manifest,
        sessionId: context.sessionId,
    });

    return verifiedShares[0].decryptionShares;
};
