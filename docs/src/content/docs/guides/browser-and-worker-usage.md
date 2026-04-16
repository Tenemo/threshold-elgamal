---
title: Browser and worker usage
description: Browser-native key generation, manifest setup, and transport-envelope usage from the root package.
sidebar:
  order: 3
---

The workflow is browser-native. Use the root package directly inside the browser or inside Web Workers for the common manifest, key, and envelope flow. Grouped public submodules remain available when you prefer narrower imports by subsystem.

## Browser flow

```typescript
import {
    createElectionManifest,
    createManifestAcceptancePayload,
    createManifestPublicationPayload,
    createRegistrationPayload,
    decryptEnvelope,
    deriveSessionId,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    hashElectionManifest,
    hashRosterEntries,
} from "threshold-elgamal";

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
    optionList: ["Budget", "Hiring"],
    scoreRange: { min: 1, max: 10 },
});

const manifestHash = await hashElectionManifest(manifest);
const sessionId = await deriveSessionId(
    manifestHash,
    rosterHash,
    "browser-session",
    "2026-04-11T12:00:00Z",
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

const plaintext = new TextEncoder().encode("browser-envelope");
const encrypted = await encryptEnvelope(
    plaintext,
    participants[1].transportPublicKey,
    {
        sessionId,
        rosterHash,
        phase: 1,
        dealerIndex: 1,
        recipientIndex: 2,
        envelopeId: "env-1-2",
        payloadType: "encrypted-dual-share",
        protocolVersion: manifestPublication.payload.protocolVersion,
        suite: "X25519",
    },
);
const decrypted = await decryptEnvelope(
    encrypted.envelope,
    participants[1].transport.privateKey,
);

console.log(manifestPublication.payload.messageType);
console.log(registration.payload.messageType);
console.log(acceptance.payload.messageType);
console.log(new TextDecoder().decode(decrypted));
```

This covers the browser-native pieces most applications need first:

- auth and transport key generation
- manifest and session setup
- signed phase-`0` payload creation
- encrypted share transport

## Keeping keys inside a worker

The library can be imported inside a worker directly:

```typescript
import {
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
} from "threshold-elgamal";

self.onmessage = async (event) => {
    const participantIndex = event.data.participantIndex as number;
    const auth = await generateAuthKeyPair({ extractable: true });
    const transport = await generateTransportKeyPair({ extractable: true });

    self.postMessage({
        participantIndex,
        authPublicKey: await exportAuthPublicKey(auth.publicKey),
        transportPublicKey: await exportTransportPublicKey(transport.publicKey),
    });
};
```

Keep the `CryptoKey` objects in the worker that created them unless you have already validated cross-thread transfer behavior in your supported runtimes.

## What stays outside the library

The library does not manage:

- worker lifecycle
- retries and reconnects
- bulletin-board posting
- wake-lock handling
- mobile lifecycle recovery
- local plaintext vote staging before DKG completion

For exact runtime constraints, read [Runtime and compatibility](./runtime-and-compatibility/).
