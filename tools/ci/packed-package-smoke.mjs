import {
    SHIPPED_PROTOCOL_VERSION,
    createBallotClosePayload,
    createDecryptionSharePayload,
    createElectionManifest,
    createTallyPublicationPayload,
    decryptEnvelope,
    deriveSessionId,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    hashElectionManifest,
    hashRosterEntries,
    majorityThreshold,
} from 'threshold-elgamal';

const packageName = 'threshold-elgamal';
/** @type {typeof import('../../src/core/public.ts')} */
const coreModule = await import(`${packageName}/core`);
/** @type {typeof import('../../src/proofs/public.ts')} */
const proofsModule = await import(`${packageName}/proofs`);
/** @type {typeof import('../../src/threshold/public.ts')} */
const thresholdModule = await import(`${packageName}/threshold`);
/** @type {typeof import('../../src/dkg/public.ts')} */
const dkgModule = await import(`${packageName}/dkg`);

const { RISTRETTO_GROUP } = coreModule;
const { createDLEQProof, verifyDLEQProof } = proofsModule;
const { combineDecryptionShares, createDecryptionShare } = thresholdModule;
const { decodePedersenShareEnvelope, encodePedersenShareEnvelope } = dkgModule;

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

const thresholdVector = {
    ciphertext: {
        c1: 'f03aa76fb871dc237db54ddd77b91430a7876beb99ae7f4047545d6cd086101c',
        c2: '805351278c30580bf6341232ffde49aab9b53b47f63c9049c16789b7fc38a83d',
    },
    sharePublicKey:
        '760df7732237a40d6c5d7c5c2f19eefb7eea951648f33465bef5fa222c667a0e',
    subsetShares: [
        {
            index: 1,
            value: 93814n,
            decryptionShare:
                'd4d45a7b49b6885c4517095b505cc78e59c838b94cc52d9277ff4c37cc5c9964',
        },
        {
            index: 3,
            value: 338226n,
            decryptionShare:
                'fce0b2c12661c0c6425f663f701717092429245ecbc90d61389aefc50063da5a',
        },
        {
            index: 5,
            value: 691270n,
            decryptionShare:
                'a6218d12d1912db37e0f6a69c664a50ef2663a8c24b91f48a125eeff72203e5f',
        },
    ],
};

const computedShares = thresholdVector.subsetShares.map((share) =>
    createDecryptionShare(thresholdVector.ciphertext, share),
);
const participantThreeShare = computedShares[1];
const revealProof = await createDLEQProof(
    thresholdVector.subsetShares[1].value,
    {
        publicKey: thresholdVector.sharePublicKey,
        ciphertext: thresholdVector.ciphertext,
        decryptionShare: participantThreeShare.value,
    },
    RISTRETTO_GROUP,
    {
        protocolVersion: SHIPPED_PROTOCOL_VERSION,
        suiteId: RISTRETTO_GROUP.name,
        manifestHash: 'aa'.repeat(32),
        sessionId: 'bb'.repeat(32),
        label: 'decryption-share-dleq',
        participantIndex: 3,
        optionIndex: 1,
    },
);
const decryptionSharePayload = await createDecryptionSharePayload(
    participants[2].auth.privateKey,
    {
        sessionId: 'bb'.repeat(32),
        manifestHash: 'aa'.repeat(32),
        participantIndex: 3,
        optionIndex: 1,
        transcriptHash: 'cc'.repeat(32),
        ballotCount: 3,
        decryptionShare: participantThreeShare.value,
        proof: revealProof,
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
    computedShares.every(
        (share, index) =>
            share.index === thresholdVector.subsetShares[index].index &&
            share.value === thresholdVector.subsetShares[index].decryptionShare,
    ),
    'Packed smoke createDecryptionShare output mismatch',
);
assert(
    (await verifyDLEQProof(
        revealProof,
        {
            publicKey: thresholdVector.sharePublicKey,
            ciphertext: thresholdVector.ciphertext,
            decryptionShare: participantThreeShare.value,
        },
        RISTRETTO_GROUP,
        {
            protocolVersion: SHIPPED_PROTOCOL_VERSION,
            suiteId: RISTRETTO_GROUP.name,
            manifestHash: 'aa'.repeat(32),
            sessionId: 'bb'.repeat(32),
            label: 'decryption-share-dleq',
            participantIndex: 3,
            optionIndex: 1,
        },
    )) === true,
    'Packed smoke DLEQ proof verification failed',
);
assert(
    decryptionSharePayload.payload.decryptionShare ===
        participantThreeShare.value,
    'Packed smoke decryption-share payload did not preserve the computed share',
);
assert(
    combineDecryptionShares(thresholdVector.ciphertext, computedShares, 20n) ===
        13n,
    'Packed smoke threshold reconstruction failed',
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
