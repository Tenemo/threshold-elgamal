import type { SignedPayload } from '../protocol/types.js';

import {
    createMajorityDkgState,
    processMajorityDkgPayload,
} from './majority-reducer.js';
import type { DKGConfigInput, DKGState, DKGTransition } from './types.js';

/**
 * Creates an empty Joint-Feldman state.
 *
 * @param config DKG configuration.
 * @returns Initial Joint-Feldman state.
 */
export const createJointFeldmanState = (config: DKGConfigInput): DKGState =>
    createMajorityDkgState(config, 'joint-feldman');

/**
 * Processes one signed payload through the Joint-Feldman log reducer.
 *
 * @param state Current Joint-Feldman state.
 * @param signedPayload Incoming signed payload.
 * @returns Deterministic state transition result.
 */
export const processJointFeldmanPayload = (
    state: DKGState,
    signedPayload: SignedPayload,
): DKGTransition => processMajorityDkgPayload(state, signedPayload);

/**
 * Replays a Joint-Feldman transcript from the initial state.
 *
 * @param config DKG configuration.
 * @param transcript Signed transcript payloads.
 * @returns Final Joint-Feldman state after replay.
 */
export const replayJointFeldmanTranscript = (
    config: DKGConfigInput,
    transcript: readonly SignedPayload[],
): DKGState => {
    let state = createJointFeldmanState(config);

    for (const payload of transcript) {
        state = processJointFeldmanPayload(state, payload).newState;
    }

    return state;
};
