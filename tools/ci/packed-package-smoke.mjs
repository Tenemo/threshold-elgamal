import {
    RISTRETTO_GROUP,
    createBallotClosePayload,
    createElectionManifest,
    createTallyPublicationPayload,
    decodePedersenShareEnvelope,
    decryptEnvelope,
    deriveSessionId,
    encodePedersenShareEnvelope,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    hashElectionManifest,
    hashRosterEntries,
    majorityThreshold,
} from 'threshold-elgamal';

const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const participants = await Promise.all(
    Array.from({ length: 3 }, async (_value, offset) => {
        const index = offset + 1;
        const auth = await generateAuthKeyPair({ extractable: true });
        const transport = await generateTransportKeyPair({
            extractable: true,
        });

        return {
            auth,
            index,
            authPublicKey: await exportAuthPublicKey(auth.publicKey),
            transport,
            transportPublicKey: await exportTransportPublicKey(
                transport.publicKey,
            ),
        };
    }),
);

const rosterHash = await hashRosterEntries(
    participants.map((participant) => ({
        participantIndex: participant.index,
        authPublicKey: participant.authPublicKey,
        transportPublicKey: participant.transportPublicKey,
    })),
);
const manifest = createElectionManifest({
    rosterHash,
    optionList: ['Option A', 'Option B'],
});
const manifestHash = await hashElectionManifest(manifest);
const sessionId = await deriveSessionId(
    manifestHash,
    rosterHash,
    'packed-smoke-nonce',
    '2026-04-11T12:00:00Z',
);

const ballotClose = await createBallotClosePayload(
    participants[0].auth.privateKey,
    {
        sessionId,
        manifestHash,
        participantIndex: participants[0].index,
        countedParticipantIndices: [3, 1, 2],
    },
);
const tallyPublication = await createTallyPublicationPayload(
    participants[0].auth.privateKey,
    {
        sessionId,
        manifestHash,
        participantIndex: participants[0].index,
        optionIndex: 1,
        transcriptHash: 'aa'.repeat(32),
        ballotCount: 3,
        decryptionParticipantIndices: [3, 1, 2],
        tally: 16n,
    },
);

const encodedShareEnvelope = encodePedersenShareEnvelope(
    {
        index: 2,
        secretValue: 7n,
        blindingValue: 13n,
    },
    RISTRETTO_GROUP.scalarByteLength,
);
const decodedShareEnvelope = decodePedersenShareEnvelope(
    new TextEncoder().encode(encodedShareEnvelope),
    2,
    'Packed smoke envelope',
);

const plaintext = new TextEncoder().encode('packed-browser-envelope');
const encrypted = await encryptEnvelope(
    plaintext,
    participants[1].transportPublicKey,
    {
        sessionId,
        rosterHash,
        phase: 1,
        dealerIndex: 1,
        recipientIndex: 2,
        envelopeId: 'env-1-2',
        payloadType: 'encrypted-dual-share',
        protocolVersion: 'v1',
        suite: 'X25519',
    },
);
const decrypted = await decryptEnvelope(
    encrypted.envelope,
    participants[1].transport.privateKey,
);
assert(
    ballotClose.payload.countedParticipantIndices.join(',') === '1,2,3',
    'Packed smoke ballot-close normalization failed',
);
assert(
    tallyPublication.payload.decryptionParticipantIndices.join(',') === '1,2,3',
    'Packed smoke tally-publication normalization failed',
);
assert(
    decodedShareEnvelope.index === 2,
    'Packed smoke Pedersen share envelope decode lost the participant index',
);
assert(
    decodedShareEnvelope.secretValue === 7n,
    'Packed smoke Pedersen share envelope decode lost the secret share',
);
assert(
    decodedShareEnvelope.blindingValue === 13n,
    'Packed smoke Pedersen share envelope decode lost the blinding share',
);
assert(
    new TextDecoder().decode(decrypted) === 'packed-browser-envelope',
    'Packed smoke transport envelope round-trip failed',
);
assert(
    majorityThreshold(3) === 2,
    'Packed smoke majority threshold helper returned the wrong threshold',
);

console.log('Packed package public API smoke test passed.');
