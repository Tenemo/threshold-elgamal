import { describe, expect, it } from 'vitest';

import { RISTRETTO_GROUP } from '#core';
import { addEncryptedValues, encryptAdditiveWithRandomness } from '#elgamal';
import {
    combineDecryptionShares,
    createDLEQProof,
    createDecryptionShare,
    prepareAggregateForDecryption,
    verifyDLEQProof,
    type AggregateDecryptionPreparationInput,
    type ProofContext,
    type Share,
} from '#root';
import { encodePoint, multiplyBase } from '#src/core/ristretto';
import { createVerifiedAggregateCiphertext } from '#src/threshold/types';

const jointSecret = 12_345n;
const jointPublicKey = encodePoint(multiplyBase(jointSecret));
const identityPoint = encodePoint(multiplyBase(0n));
const manifestHash = 'aa'.repeat(32);
const transcriptHash = 'bb'.repeat(32);
const sessionId = 'session-identity-aggregate';

const thresholdShares: readonly Share[] = [
    {
        index: 1,
        value: jointSecret + 77n,
    },
    {
        index: 2,
        value: jointSecret + 154n,
    },
];

const proofContext = (
    participantIndex: number,
    optionIndex: number,
): ProofContext => ({
    protocolVersion: 'v1',
    suiteId: RISTRETTO_GROUP.name,
    manifestHash,
    sessionId,
    label: 'decryption-share-dleq',
    participantIndex,
    optionIndex,
});

describe('decryption aggregate preparation', () => {
    it('returns the original aggregate when c1 is already non-identity', () => {
        const aggregate = createVerifiedAggregateCiphertext(
            transcriptHash,
            encryptAdditiveWithRandomness(6n, jointPublicKey, 7n, 20n),
            1,
        );

        const prepared = prepareAggregateForDecryption({
            aggregate,
            publicKey: jointPublicKey,
            protocolVersion: 'v1',
            manifestHash,
            sessionId,
            optionIndex: 1,
        });

        expect(prepared).toBe(aggregate);
    });

    it('deterministically rerandomizes identity aggregates while preserving threshold recovery', async () => {
        const aggregateCiphertext = addEncryptedValues(
            encryptAdditiveWithRandomness(6n, jointPublicKey, 7n, 20n),
            encryptAdditiveWithRandomness(
                7n,
                jointPublicKey,
                RISTRETTO_GROUP.q - 7n,
                20n,
            ),
        );
        const aggregate = createVerifiedAggregateCiphertext(
            transcriptHash,
            aggregateCiphertext,
            2,
        );
        const preparationInput: AggregateDecryptionPreparationInput = {
            aggregate,
            publicKey: jointPublicKey,
            protocolVersion: 'v1',
            manifestHash,
            sessionId,
            optionIndex: 1,
        };

        expect(aggregate.ciphertext.c1).toBe(identityPoint);

        const prepared = prepareAggregateForDecryption(preparationInput);
        const preparedAgain = prepareAggregateForDecryption(preparationInput);
        const preparedForOtherOption = prepareAggregateForDecryption({
            ...preparationInput,
            optionIndex: 2,
        });

        expect(prepared.transcriptHash).toBe(aggregate.transcriptHash);
        expect(prepared.ballotCount).toBe(aggregate.ballotCount);
        expect(prepared.ciphertext.c1).not.toBe(identityPoint);
        expect(prepared.ciphertext).toEqual(preparedAgain.ciphertext);
        expect(prepared.ciphertext).not.toEqual(
            preparedForOtherOption.ciphertext,
        );

        const rawShares = thresholdShares.map((share) =>
            createDecryptionShare(aggregate.ciphertext, share),
        );
        expect(rawShares.map((share) => share.value)).toEqual([
            identityPoint,
            identityPoint,
        ]);
        expect(
            combineDecryptionShares(aggregate.ciphertext, rawShares, 20n),
        ).toBe(13n);
        await expect(
            createDLEQProof(
                thresholdShares[0].value,
                {
                    publicKey: encodePoint(
                        multiplyBase(thresholdShares[0].value),
                    ),
                    ciphertext: aggregate.ciphertext,
                    decryptionShare: rawShares[0].value,
                },
                RISTRETTO_GROUP,
                proofContext(thresholdShares[0].index, 1),
            ),
        ).rejects.toThrow(
            'Element is not a valid non-identity Ristretto point',
        );

        const preparedShares = thresholdShares.map((share) =>
            createDecryptionShare(prepared.ciphertext, share),
        );
        expect(
            combineDecryptionShares(prepared.ciphertext, preparedShares, 20n),
        ).toBe(13n);

        const proofs = await Promise.all(
            thresholdShares.map((share, offset) =>
                createDLEQProof(
                    share.value,
                    {
                        publicKey: encodePoint(multiplyBase(share.value)),
                        ciphertext: prepared.ciphertext,
                        decryptionShare: preparedShares[offset].value,
                    },
                    RISTRETTO_GROUP,
                    proofContext(share.index, 1),
                ),
            ),
        );

        await expect(
            Promise.all(
                thresholdShares.map((share, offset) =>
                    verifyDLEQProof(
                        proofs[offset],
                        {
                            publicKey: encodePoint(multiplyBase(share.value)),
                            ciphertext: prepared.ciphertext,
                            decryptionShare: preparedShares[offset].value,
                        },
                        RISTRETTO_GROUP,
                        proofContext(share.index, 1),
                    ),
                ),
            ),
        ).resolves.toEqual([true, true]);
    });
});
