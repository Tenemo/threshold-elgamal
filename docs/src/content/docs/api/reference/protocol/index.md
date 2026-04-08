---
title: "protocol"
description: "Generated reference page for the `protocol` export surface."
editUrl: false
sidebar:
  order: 6
---
[**threshold-elgamal**](../)

***

[threshold-elgamal](../modules/) / protocol

# protocol

Canonical protocol payload, manifest, ordering, and transcript helpers.

This module defines the typed payload surface used by the higher-level
transport and DKG reducers.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [BallotSubmissionPayload](type-aliases/BallotSubmissionPayload/) | Signed additive ballot payload for one participant and one option slot. |
| [BallotTranscriptEntry](type-aliases/BallotTranscriptEntry/) | Verified additive ballot record used in transcript aggregation. |
| [BaseProtocolPayload](type-aliases/BaseProtocolPayload/) | Shared fields present on every unsigned protocol payload. |
| [CanonicalJsonOptions](type-aliases/CanonicalJsonOptions/) | Options controlling canonical JSON serialization behavior. |
| [CanonicalJsonPrimitive](type-aliases/CanonicalJsonPrimitive/) | Primitive value accepted by the canonical JSON serializer. |
| [CanonicalJsonValue](type-aliases/CanonicalJsonValue/) | Recursive JSON-like value accepted by the canonical JSON serializer. |
| [CeremonyRestartPayload](type-aliases/CeremonyRestartPayload/) | Signed link from a restarted ceremony to the aborted prior attempt. |
| [ComplaintPayload](type-aliases/ComplaintPayload/) | Complaint payload against a dealer envelope or share. |
| [ComplaintReason](type-aliases/ComplaintReason/) | Complaint reasons recognized by the protocol layer. |
| [ComplaintResolutionPayload](type-aliases/ComplaintResolutionPayload/) | Dealer-signed complaint-resolution payload carrying the sender-ephemeral private key that lets every verifier independently resolve one complaint. |
| [DecryptionSharePayload](type-aliases/DecryptionSharePayload/) | Signed threshold decryption-share payload tied to a locally recomputed additive aggregate transcript. |
| [ElectionManifest](type-aliases/ElectionManifest/) | Canonical election-manifest shape bound into protocol transcripts. |
| [EncodedCiphertext](type-aliases/EncodedCiphertext/) | Canonical additive ciphertext encoding used by protocol payloads. |
| [EncodedCompactProof](type-aliases/EncodedCompactProof/) | Canonical compact Schnorr or DLEQ proof encoding used by payloads. |
| [EncodedDisjunctiveBranch](type-aliases/EncodedDisjunctiveBranch/) | Canonical CDS94 proof branch encoding used by ballot payloads. |
| [EncodedDisjunctiveProof](type-aliases/EncodedDisjunctiveProof/) | Canonical CDS94 proof encoding used by ballot payloads. |
| [EncryptedDualSharePayload](type-aliases/EncryptedDualSharePayload/) | Encrypted share-envelope payload for the share-distribution step. |
| [FeldmanCommitmentPayload](type-aliases/FeldmanCommitmentPayload/) | Broadcast payload carrying Feldman commitments and coefficient proofs. |
| [FeldmanShareRevealPayload](type-aliases/FeldmanShareRevealPayload/) | Public share-reveal payload used for complaint-driven reconstruction. |
| [KeyDerivationConfirmation](type-aliases/KeyDerivationConfirmation/) | Final key-derivation confirmation payload. |
| [ManifestAcceptancePayload](type-aliases/ManifestAcceptancePayload/) | Participant-signed manifest acceptance payload. |
| [ManifestPublicationPayload](type-aliases/ManifestPublicationPayload/) | Signed manifest-publication payload anchoring the frozen manifest. |
| [PedersenCommitmentPayload](type-aliases/PedersenCommitmentPayload/) | Broadcast payload carrying Pedersen coefficient commitments. |
| [ProtocolMessageType](type-aliases/ProtocolMessageType/) | Canonical protocol payload type identifiers. |
| [ProtocolPayload](type-aliases/ProtocolPayload/) | Union of all unsigned protocol payload shapes. |
| [RegistrationPayload](type-aliases/RegistrationPayload/) | Registration payload carrying ceremony auth and transport keys. |
| [RestartReasonCode](type-aliases/RestartReasonCode/) | Public restart reason codes for aborted ceremonies. |
| [RosterEntry](type-aliases/RosterEntry/) | Roster entry used for deterministic roster hashing. |
| [SignedPayload](type-aliases/SignedPayload/) | Unsigned protocol payload paired with an authentication signature. |
| [TallyPublicationPayload](type-aliases/TallyPublicationPayload/) | Signed tally-publication payload for the recovered additive tally. |
| [VerifiedBallotAggregation](type-aliases/VerifiedBallotAggregation/) | Result of verifying and aggregating a ballot transcript. |
| [VerifiedDecryptionSharePayload](type-aliases/VerifiedDecryptionSharePayload/) | Verified typed decryption-share payload. |
| [VerifiedProtocolSignatures](type-aliases/VerifiedProtocolSignatures/) | Verified protocol-signature result with the frozen registration roster. |
| [VerifiedPublishedVotingResult](type-aliases/VerifiedPublishedVotingResult/) | Verified published tally and all of its reusable sub-results. |
| [VerifyAndAggregateBallotsInput](type-aliases/VerifyAndAggregateBallotsInput/) | Input bundle for ballot verification and aggregation. |
| [VerifyBallotSubmissionPayloadsInput](type-aliases/VerifyBallotSubmissionPayloadsInput/) | Input bundle for verifying typed ballot payloads. |
| [VerifyDecryptionSharePayloadsInput](type-aliases/VerifyDecryptionSharePayloadsInput/) | Input bundle for verifying typed decryption-share payloads. |
| [VerifyPublishedVotingResultInput](type-aliases/VerifyPublishedVotingResultInput/) | Input bundle for verifying one full published tally. |

## Functions

| Function | Description |
| ------ | ------ |
| [canonicalizeElectionManifest](functions/canonicalizeElectionManifest/) | Canonically serializes an election manifest. |
| [canonicalizeJson](functions/canonicalizeJson/) | Canonically serializes JSON-compatible payloads with sorted keys and no insignificant whitespace. |
| [canonicalizeRosterEntries](functions/canonicalizeRosterEntries/) | Canonically serializes a frozen roster view. |
| [canonicalTranscriptBytes](functions/canonicalTranscriptBytes/) | Canonically serializes the ordered unsigned payload set for a transcript. |
| [canonicalUnsignedPayloadBytes](functions/canonicalUnsignedPayloadBytes/) | Serializes the unsigned payload into canonical bytes. |
| [classifySlotConflict](functions/classifySlotConflict/) | Classifies how two signed payloads for the same slot relate to one another. |
| [compareProtocolPayloads](functions/compareProtocolPayloads/) | Deterministically compares payloads for transcript ordering. |
| [decodeCiphertext](functions/decodeCiphertext/) | Decodes a protocol ciphertext into bigint components. |
| [decodeCompactProof](functions/decodeCompactProof/) | Decodes a protocol compact proof into bigint fields. |
| [decodeDisjunctiveProof](functions/decodeDisjunctiveProof/) | Decodes a protocol disjunctive proof into bigint fields. |
| [defaultMinimumPublicationThreshold](functions/defaultMinimumPublicationThreshold/) | Returns the minimum publication threshold compatible with the shipped honest-majority policy. |
| [deriveSessionId](functions/deriveSessionId/) | Derives a globally unique session identifier from the frozen setup values. |
| [encodeCiphertext](functions/encodeCiphertext/) | Encodes an additive ciphertext into fixed-width protocol hex. |
| [encodeCompactProof](functions/encodeCompactProof/) | Encodes a compact challenge-response proof into fixed-width protocol hex. |
| [encodeDisjunctiveProof](functions/encodeDisjunctiveProof/) | Encodes a disjunctive proof into fixed-width protocol hex. |
| [formatSessionFingerprint](functions/formatSessionFingerprint/) | Formats the first 32 hexadecimal characters of a transcript hash as a session fingerprint for out-of-band comparison. |
| [hashAcceptedBallots](functions/hashAcceptedBallots/) | Hashes the accepted ballot transcript deterministically. |
| [hashElectionManifest](functions/hashElectionManifest/) | Hashes a canonical election manifest with SHA-256. |
| [hashProtocolTranscript](functions/hashProtocolTranscript/) | Hashes an ordered transcript of unsigned protocol payloads. |
| [hashRosterEntries](functions/hashRosterEntries/) | Hashes a deterministic roster view with SHA-256. |
| [manifestScoreDomain](functions/manifestScoreDomain/) | Builds the ordered score domain implied by the manifest. |
| [payloadSlotKey](functions/payloadSlotKey/) | Computes the canonical slot key used for idempotence and equivocation checks. |
| [sortProtocolPayloads](functions/sortProtocolPayloads/) | Returns a sorted copy of protocol payloads using the canonical transcript ordering rule. |
| [validateElectionManifest](functions/validateElectionManifest/) | Validates the supported election-manifest invariants for the shipped score-voting workflow. |
| [verifyAndAggregateBallots](functions/verifyAndAggregateBallots/) | Verifies disjunctive ballot proofs, rejects duplicate ballot slots, and recomputes the additive aggregate deterministically. |
| [verifyBallotSubmissionPayloads](functions/verifyBallotSubmissionPayloads/) | Verifies typed ballot-submission payloads and recomputes the aggregate tally ciphertext from the accepted ballot transcript. |
| [verifyDecryptionSharePayloads](functions/verifyDecryptionSharePayloads/) | Verifies typed decryption-share payloads against the DKG transcript-derived trustee keys and one locally recomputed aggregate ciphertext. |
| [verifyPublishedVotingResult](functions/verifyPublishedVotingResult/) | Verifies one published tally from the signed DKG log, typed ballot payloads, typed decryption-share payloads, and an optional tally-publication record. |
| [verifySignedProtocolPayloads](functions/verifySignedProtocolPayloads/) | Verifies protocol payload signatures against the registration roster carried in the transcript. |
