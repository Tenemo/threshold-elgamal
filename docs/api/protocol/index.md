[**threshold-elgamal**](../index.md)

***

[threshold-elgamal](../modules.md) / protocol

# protocol

Canonical protocol payload, manifest, ordering, and transcript helpers.

This module defines the typed payload surface used by the higher-level
transport and DKG reducers.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [BaseProtocolPayload](type-aliases/BaseProtocolPayload.md) | Shared fields present on every unsigned protocol payload. |
| [CanonicalJsonOptions](type-aliases/CanonicalJsonOptions.md) | Options controlling canonical JSON serialization behavior. |
| [CanonicalJsonPrimitive](type-aliases/CanonicalJsonPrimitive.md) | Primitive value accepted by the canonical JSON serializer. |
| [CanonicalJsonValue](type-aliases/CanonicalJsonValue.md) | Recursive JSON-like value accepted by the canonical JSON serializer. |
| [ComplaintPayload](type-aliases/ComplaintPayload.md) | Complaint payload against a dealer envelope or share. |
| [ComplaintReason](type-aliases/ComplaintReason.md) | Complaint reasons recognized by the protocol layer. |
| [ElectionManifest](type-aliases/ElectionManifest.md) | Canonical election-manifest shape bound into protocol transcripts. |
| [EncryptedDualSharePayload](type-aliases/EncryptedDualSharePayload.md) | Encrypted share-envelope payload for the share-distribution step. |
| [FeldmanCommitmentPayload](type-aliases/FeldmanCommitmentPayload.md) | Broadcast payload carrying Feldman commitments and coefficient proofs. |
| [FeldmanShareRevealPayload](type-aliases/FeldmanShareRevealPayload.md) | Public share-reveal payload used for complaint-driven reconstruction. |
| [KeyDerivationConfirmation](type-aliases/KeyDerivationConfirmation.md) | Final key-derivation confirmation payload. |
| [ManifestAcceptancePayload](type-aliases/ManifestAcceptancePayload.md) | Participant-signed manifest acceptance payload. |
| [PedersenCommitmentPayload](type-aliases/PedersenCommitmentPayload.md) | Broadcast payload carrying Pedersen coefficient commitments. |
| [ProtocolMessageType](type-aliases/ProtocolMessageType.md) | Canonical protocol payload type identifiers. |
| [ProtocolPayload](type-aliases/ProtocolPayload.md) | Union of all unsigned protocol payload shapes. |
| [RegistrationPayload](type-aliases/RegistrationPayload.md) | Registration payload carrying ceremony auth and transport keys. |
| [RestartReasonCode](type-aliases/RestartReasonCode.md) | Public restart reason codes for aborted ceremonies. |
| [SignedPayload](type-aliases/SignedPayload.md) | Unsigned protocol payload paired with an authentication signature. |

## Functions

| Function | Description |
| ------ | ------ |
| [canonicalizeElectionManifest](functions/canonicalizeElectionManifest.md) | Canonically serializes an election manifest. |
| [canonicalizeJson](functions/canonicalizeJson.md) | Canonically serializes JSON-compatible payloads with sorted keys and no insignificant whitespace. |
| [canonicalTranscriptBytes](functions/canonicalTranscriptBytes.md) | Canonically serializes the ordered unsigned payload set for a transcript. |
| [canonicalUnsignedPayloadBytes](functions/canonicalUnsignedPayloadBytes.md) | Serializes the unsigned payload into canonical bytes. |
| [classifySlotConflict](functions/classifySlotConflict.md) | Classifies how two signed payloads for the same slot relate to one another. |
| [compareProtocolPayloads](functions/compareProtocolPayloads.md) | Deterministically compares payloads for transcript ordering. |
| [deriveSessionId](functions/deriveSessionId.md) | Derives a globally unique session identifier from the frozen setup values. |
| [formatSessionFingerprint](functions/formatSessionFingerprint.md) | Formats the first 32 hexadecimal characters of a transcript hash as a session fingerprint for out-of-band comparison. |
| [hashElectionManifest](functions/hashElectionManifest.md) | Hashes a canonical election manifest with SHA-256. |
| [hashProtocolTranscript](functions/hashProtocolTranscript.md) | Hashes an ordered transcript of unsigned protocol payloads. |
| [payloadSlotKey](functions/payloadSlotKey.md) | Computes the canonical slot key used for idempotence and equivocation checks. |
| [sortProtocolPayloads](functions/sortProtocolPayloads.md) | Returns a sorted copy of protocol payloads using the canonical transcript ordering rule. |
