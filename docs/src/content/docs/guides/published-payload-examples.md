---
title: Published payload examples
description: Concrete signed payload shapes for posting, storing, and verifying the public board.
sidebar:
  order: 4
---

All public protocol builders return the same outer shape:

```json
{
  "payload": { "...": "..." },
  "signature": "..."
}
```

The `payload` object is already JSON-safe. Group elements, scalars, proofs, and signatures are string-encoded before publication. Every signed payload also carries the built-in verifier namespace exported as `SHIPPED_PROTOCOL_VERSION`, so the JSON examples below show `protocolVersion: "v1"`.

## Manifest publication

```json
{
  "payload": {
    "protocolVersion": "v1",
    "sessionId": "6b7d...8e91",
    "manifestHash": "9e17...d34a",
    "phase": 0,
    "participantIndex": 1,
    "messageType": "manifest-publication",
    "manifest": {
      "rosterHash": "b992...70ce",
      "optionList": ["Budget", "Hiring"]
    }
  },
  "signature": "0bb4...43fa"
}
```

## Registration

```json
{
  "payload": {
    "protocolVersion": "v1",
    "sessionId": "6b7d...8e91",
    "manifestHash": "9e17...d34a",
    "phase": 0,
    "participantIndex": 2,
    "messageType": "registration",
    "rosterHash": "b992...70ce",
    "authPublicKey": "d011...ad44",
    "transportPublicKey": "6c3a...ef91"
  },
  "signature": "d5a0...99b2"
}
```

## Manifest acceptance

```json
{
  "payload": {
    "protocolVersion": "v1",
    "sessionId": "6b7d...8e91",
    "manifestHash": "9e17...d34a",
    "phase": 0,
    "participantIndex": 2,
    "messageType": "manifest-acceptance",
    "rosterHash": "b992...70ce",
    "assignedParticipantIndex": 2
  },
  "signature": "51b0...bc33"
}
```

## Ballot submission

```json
{
  "payload": {
    "protocolVersion": "v1",
    "sessionId": "6b7d...8e91",
    "manifestHash": "9e17...d34a",
    "phase": 5,
    "participantIndex": 2,
    "messageType": "ballot-submission",
    "optionIndex": 1,
    "ciphertext": {
      "c1": "af91...8b20",
      "c2": "8a37...99c1"
    },
    "proof": {
      "branches": [
        {
          "challenge": "6d01...4ef7",
          "response": "8c10...1a02"
        },
        {
          "challenge": "f842...0071",
          "response": "44ab...6cc5"
        }
      ]
    }
  },
  "signature": "692d...75b4"
}
```

## Ballot close

```json
{
  "payload": {
    "protocolVersion": "v1",
    "sessionId": "6b7d...8e91",
    "manifestHash": "9e17...d34a",
    "phase": 6,
    "participantIndex": 1,
    "messageType": "ballot-close",
    "countedParticipantIndices": [1, 2, 3, 4]
  },
  "signature": "dc77...24f0"
}
```

The builder sorts and validates the participant indices before signing. Feed it unsorted input only if you want the canonical sorted result back.

## Decryption share

```json
{
  "payload": {
    "protocolVersion": "v1",
    "sessionId": "6b7d...8e91",
    "manifestHash": "9e17...d34a",
    "phase": 7,
    "participantIndex": 2,
    "messageType": "decryption-share",
    "optionIndex": 1,
    "transcriptHash": "2ad4...dcb8",
    "ballotCount": 4,
    "decryptionShare": "73b1...4c90",
    "proof": {
      "challenge": "ce48...17a5",
      "response": "2ab9...ef40"
    }
  },
  "signature": "4f8b...e030"
}
```

The signed payload does not derive the partial share for you. First prepare the accepted aggregate with `prepareAggregateForDecryption(...)` from `threshold-elgamal/threshold`, then compute the share with `createDecryptionShare(...)` from `threshold-elgamal/threshold`, build the matching DLEQ proof with `createDLEQProof(...)` from `threshold-elgamal/proofs`, and finally sign the published object with `createDecryptionSharePayload(...)` from `threshold-elgamal`.

## Tally publication

```json
{
  "payload": {
    "protocolVersion": "v1",
    "sessionId": "6b7d...8e91",
    "manifestHash": "9e17...d34a",
    "phase": 8,
    "participantIndex": 1,
    "messageType": "tally-publication",
    "optionIndex": 1,
    "transcriptHash": "2ad4...dcb8",
    "ballotCount": 4,
    "tally": "1400000000000000000000000000000000000000000000000000000000000000",
    "decryptionParticipantIndices": [1, 2, 3]
  },
  "signature": "f09c...a441"
}
```

The tally is string-encoded inside the published payload, not stored as a JSON number or JavaScript `bigint`.

The remaining DKG payloads such as phase checkpoints, Pedersen commitments, encrypted dual shares, Feldman commitments, and key-derivation confirmations use the same outer `{ payload, signature }` shape.

## Posting, storing, and restoring payloads

Because the public payloads are plain JSON-safe objects, you can post and store them directly:

```typescript
const body = JSON.stringify(signedPayload);

await fetch(boardUrl, {
    method: "POST",
    headers: {
        "content-type": "application/json",
    },
    body,
});

const restored = JSON.parse(body);
```

If you store verifier output instead of published payloads, convert `bigint` values such as tallies to strings first. For verifier usage, read [Verifying a public board](./verifying-a-public-board/).
