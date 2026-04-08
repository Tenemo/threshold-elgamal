---
title: "dkg"
description: "Generated reference page for the `dkg` export surface."
editUrl: false
sidebar:
  order: 8
---
[**threshold-elgamal**](../)

***

[threshold-elgamal](../modules/) / dkg

# dkg

Log-driven DKG reducers and reconstruction helpers.

This module contains pure state-machine helpers for Joint-Feldman and GJKR,
along with QUAL computation and transcript replay utilities.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [AcceptedShareContribution](type-aliases/AcceptedShareContribution/) | Share contribution accepted from one qualified dealer. |
| [DKGConfig](type-aliases/DKGConfig/) | Resolved static configuration for a log-driven DKG reducer. |
| [DKGError](type-aliases/DKGError/) | Structured DKG reducer error. |
| [DKGPhase](type-aliases/DKGPhase/) | Reducer step markers used by the log-driven DKG state machines. |
| [DKGProtocol](type-aliases/DKGProtocol/) | Supported DKG reducer variants. |
| [DKGState](type-aliases/DKGState/) | Snapshot of a log-driven DKG reducer state. |
| [DKGTransition](type-aliases/DKGTransition/) | Deterministic state transition result for one incoming payload. |
| [MajorityDKGConfigInput](type-aliases/MajorityDKGConfigInput/) | Supported majority-only input for a log-driven DKG reducer. |
| [VerifiedDKGTranscript](type-aliases/VerifiedDKGTranscript/) | Verified DKG transcript result with reusable derived ceremony material. |
| [VerifyDKGTranscriptInput](type-aliases/VerifyDKGTranscriptInput/) | Input bundle for verifying a DKG transcript. |

## Functions

| Function | Description |
| ------ | ------ |
| [appendTranscriptPayload](functions/appendTranscriptPayload/) | Appends one payload to the transcript while enforcing slot idempotence and equivocation detection. |
| [computeQual](functions/computeQual/) | Computes QUAL from the frozen participant roster and accepted complaint set. |
| [createBaseState](functions/createBaseState/) | Creates the initial empty DKG reducer state. |
| [createGjkrState](functions/createGjkrState/) | Creates an empty GJKR state. |
| [createJointFeldmanState](functions/createJointFeldmanState/) | Creates an empty Joint-Feldman state. |
| [deriveFinalShare](functions/deriveFinalShare/) | Derives one participant's final share by summing accepted share contributions from qualified dealers. |
| [deriveJointPublicKey](functions/deriveJointPublicKey/) | Derives the qualified joint public key from the constant Feldman commitments. |
| [deriveQualifiedParticipantIndices](functions/deriveQualifiedParticipantIndices/) | Derives the qualified participant set from accepted complaint outcomes. |
| [deriveTranscriptVerificationKey](functions/deriveTranscriptVerificationKey/) | Derives the transcript verification key `Y_j` for one participant index from published Feldman commitments. |
| [deriveTranscriptVerificationKeys](functions/deriveTranscriptVerificationKeys/) | Derives transcript verification keys for multiple participant indices. |
| [processGjkrPayload](functions/processGjkrPayload/) | Processes one signed payload through the GJKR log reducer. |
| [processJointFeldmanPayload](functions/processJointFeldmanPayload/) | Processes one signed payload through the Joint-Feldman log reducer. |
| [reconstructSecretFromShares](functions/reconstructSecretFromShares/) | Reconstructs the polynomial constant term from indexed Shamir shares. |
| [replayGjkrTranscript](functions/replayGjkrTranscript/) | Replays a GJKR transcript from the initial state. |
| [replayJointFeldmanTranscript](functions/replayJointFeldmanTranscript/) | Replays a Joint-Feldman transcript from the initial state. |
| [validateCommonPayload](functions/validateCommonPayload/) | Validates session-level fields shared by every DKG payload. |
| [verifyDKGTranscript](functions/verifyDKGTranscript/) | Verifies a DKG transcript, its signatures, Feldman extraction proofs, accepted complaint outcomes, `qualHash`, and the announced joint public key. |
| [withError](functions/withError/) | Builds a no-op transition carrying one structured reducer error. |
