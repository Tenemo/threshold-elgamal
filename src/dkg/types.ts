import type { GroupIdentifier } from '../core/types.js';
import type { ComplaintPayload, SignedPayload } from '../protocol/types.js';

/** Supported DKG reducer variants. */
export type DKGProtocol = 'joint-feldman' | 'gjkr';
/** Reducer step markers used by the log-driven DKG state machines. */
export type DKGPhase = 0 | 1 | 2 | 3 | 4 | 'aborted' | 'completed';

/** Structured DKG reducer error. */
export type DKGError = {
    readonly code: string;
    readonly message: string;
};

/** Supported strict-majority DKG input for a log-driven reducer. */
export type DKGConfigInput = {
    readonly protocol: DKGProtocol;
    readonly sessionId: string;
    readonly manifestHash: string;
    readonly group: GroupIdentifier;
    readonly participantCount: number;
    readonly threshold: number;
};

/** Resolved static configuration for a log-driven DKG reducer. */
export type DKGConfig = DKGConfigInput;

/** Snapshot of a log-driven DKG reducer state. */
export type DKGState = {
    readonly config: DKGConfig;
    readonly phase: DKGPhase;
    readonly manifestAccepted: readonly number[];
    readonly qual: readonly number[];
    readonly complaints: readonly ComplaintPayload[];
    readonly transcript: readonly SignedPayload[];
    readonly abortReason?: string;
};

/** Deterministic state transition result for one incoming payload. */
export type DKGTransition = {
    readonly newState: DKGState;
    readonly outgoingPayloads: readonly SignedPayload[];
    readonly errors: readonly DKGError[];
};
