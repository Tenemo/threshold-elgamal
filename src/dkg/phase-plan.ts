import type {
    ProtocolMessageType,
    PhaseCheckpointPayload,
} from '../protocol/types.js';

import type { DKGProtocol } from './types.js';

const GJKR_PHASE_PLAN: Readonly<Record<ProtocolMessageType, number | null>> = {
    'manifest-publication': 0,
    registration: 0,
    'manifest-acceptance': 0,
    'phase-checkpoint': null,
    'pedersen-commitment': 1,
    'encrypted-dual-share': 1,
    complaint: 2,
    'complaint-resolution': 2,
    'feldman-commitment': 3,
    'feldman-share-reveal': 3,
    'key-derivation-confirmation': 4,
    'ballot-submission': null,
    'decryption-share': null,
    'tally-publication': null,
    'ceremony-restart': null,
};

const JOINT_FELDMAN_PHASE_PLAN: Readonly<
    Record<ProtocolMessageType, number | null>
> = {
    'manifest-publication': 0,
    registration: 0,
    'manifest-acceptance': 0,
    'phase-checkpoint': null,
    'pedersen-commitment': null,
    'encrypted-dual-share': 1,
    complaint: 2,
    'complaint-resolution': 2,
    'feldman-commitment': 1,
    'feldman-share-reveal': 2,
    'key-derivation-confirmation': 3,
    'ballot-submission': null,
    'decryption-share': null,
    'tally-publication': null,
    'ceremony-restart': null,
};

export const expectedDkgPhase = (
    protocol: DKGProtocol,
    messageType: ProtocolMessageType,
    payload?: PhaseCheckpointPayload,
): number | null =>
    messageType === 'phase-checkpoint'
        ? (payload?.checkpointPhase ?? null)
        : protocol === 'gjkr'
          ? GJKR_PHASE_PLAN[messageType]
          : JOINT_FELDMAN_PHASE_PLAN[messageType];
