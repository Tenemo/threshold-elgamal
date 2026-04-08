[**threshold-elgamal**](../index.md)

***

[threshold-elgamal](../modules.md) / dkg

# dkg

Log-driven DKG reducers and reconstruction helpers.

This module contains pure state-machine helpers for Joint-Feldman and GJKR,
along with QUAL computation and transcript replay utilities.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [DKGConfig](type-aliases/DKGConfig.md) | Static configuration for a log-driven DKG reducer. |
| [DKGError](type-aliases/DKGError.md) | Structured DKG reducer error. |
| [DKGPhase](type-aliases/DKGPhase.md) | Reducer phases used by the log-driven DKG state machines. |
| [DKGProtocol](type-aliases/DKGProtocol.md) | Supported DKG reducer variants. |
| [DKGState](type-aliases/DKGState.md) | Snapshot of a log-driven DKG reducer state. |
| [DKGTransition](type-aliases/DKGTransition.md) | Deterministic state transition result for one incoming payload. |

## Functions

| Function | Description |
| ------ | ------ |
| [appendTranscriptPayload](functions/appendTranscriptPayload.md) | Appends one payload to the transcript while enforcing slot idempotence and equivocation detection. |
| [computeQual](functions/computeQual.md) | Computes QUAL from the frozen participant roster and accepted complaint set. |
| [createBaseState](functions/createBaseState.md) | Creates the initial empty DKG reducer state. |
| [createGjkrState](functions/createGjkrState.md) | Creates an empty GJKR state. |
| [createJointFeldmanState](functions/createJointFeldmanState.md) | Creates an empty Joint-Feldman state. |
| [processGjkrPayload](functions/processGjkrPayload.md) | Processes one signed payload through the GJKR log reducer. |
| [processJointFeldmanPayload](functions/processJointFeldmanPayload.md) | Processes one signed payload through the Joint-Feldman log reducer. |
| [reconstructSecretFromShares](functions/reconstructSecretFromShares.md) | Reconstructs the polynomial constant term from indexed Shamir shares. |
| [replayGjkrTranscript](functions/replayGjkrTranscript.md) | Replays a GJKR transcript from the initial state. |
| [replayJointFeldmanTranscript](functions/replayJointFeldmanTranscript.md) | Replays a Joint-Feldman transcript from the initial state. |
| [validateCommonPayload](functions/validateCommonPayload.md) | Validates session-level fields shared by every DKG payload. |
| [withError](functions/withError.md) | Builds a no-op transition carrying one structured reducer error. |
