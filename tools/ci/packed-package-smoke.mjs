import {
    RISTRETTO_GROUP,
    createBallotClosePayload,
    createElectionManifest,
    createManifestAcceptancePayload,
    createManifestPublicationPayload,
    createRegistrationPayload,
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
    scoreVotingDomain,
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

const manifestPublication = await createManifestPublicationPayload(
    participants[0].auth.privateKey,
    {
        manifest,
        manifestHash,
        participantIndex: participants[0].index,
        sessionId,
    },
);
const registration = await createRegistrationPayload(
    participants[1].auth.privateKey,
    {
        authPublicKey: participants[1].authPublicKey,
        manifestHash,
        participantIndex: participants[1].index,
        rosterHash,
        sessionId,
        transportPublicKey: participants[1].transportPublicKey,
    },
);
const acceptance = await createManifestAcceptancePayload(
    participants[2].auth.privateKey,
    {
        assignedParticipantIndex: participants[2].index,
        manifestHash,
        participantIndex: participants[2].index,
        rosterHash,
        sessionId,
    },
);
const ballotClose = await createBallotClosePayload(
    participants[0].auth.privateKey,
    {
        sessionId,
        manifestHash,
        participantIndex: participants[0].index,
        includedParticipantIndices: [3, 1, 2],
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
const scoreDomain = scoreVotingDomain().map((value) => value.toString());

assert(
    manifestPublication.payload.messageType === 'manifest-publication',
    'Packed smoke manifest publication builder failed',
);
assert(
    registration.payload.messageType === 'registration',
    'Packed smoke registration builder failed',
);
assert(
    acceptance.payload.messageType === 'manifest-acceptance',
    'Packed smoke acceptance builder failed',
);
assert(
    ballotClose.payload.includedParticipantIndices.join(',') === '1,2,3',
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
assert(
    scoreDomain.join(',') === '1,2,3,4,5,6,7,8,9,10',
    'Packed smoke score voting domain helper returned the wrong domain',
);

console.log('Packed package public API smoke test passed.');
