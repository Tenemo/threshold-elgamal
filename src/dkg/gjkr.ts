import type { SignedPayload } from '../protocol/types.js';

import {
    createMajorityDkgState,
    processMajorityDkgPayload,
} from './majority-reducer.js';
import type { DKGConfigInput, DKGState, DKGTransition } from './types.js';

/**
 * Creates an empty GJKR state.
 *
 * @param config DKG configuration.
 * @returns Initial GJKR state.
 */
export const createGjkrState = (config: DKGConfigInput): DKGState =>
    createMajorityDkgState(config);

/**
 * Processes one signed payload through the GJKR log reducer.
 *
 * @param state Current GJKR state.
 * @param signedPayload Incoming signed payload.
 * @returns Deterministic state transition result.
 */
export const processGjkrPayload = (
    state: DKGState,
    signedPayload: SignedPayload,
): DKGTransition => processMajorityDkgPayload(state, signedPayload);

/**
 * Replays a GJKR transcript from the initial state.
 *
 * @param config DKG configuration.
 * @param transcript Signed transcript payloads.
 * @returns Final GJKR state after replay.
 */
export const replayGjkrTranscript = (
    config: DKGConfigInput,
    transcript: readonly SignedPayload[],
): DKGState => {
    let state = createGjkrState(config);

    for (const payload of transcript) {
        state = processGjkrPayload(state, payload).newState;
    }

    return state;
};
