import { describe, expect, it } from 'vitest';

import { createTallyPublicationPayload, generateAuthKeyPair } from '#root';

describe('browser public surface', () => {
    it('rejects duplicate decryption participant indices in tally publication payloads', async () => {
        const auth = await generateAuthKeyPair({ extractable: true });

        await expect(
            createTallyPublicationPayload(auth.privateKey, {
                sessionId: 'session',
                manifestHash: 'aa'.repeat(32),
                participantIndex: 1,
                optionIndex: 1,
                transcriptHash: 'bb'.repeat(32),
                ballotCount: 3,
                decryptionParticipantIndices: [1, 2, 2],
                tally: 7n,
            }),
        ).rejects.toThrow('Decryption participant indices must be unique');
    });
});
