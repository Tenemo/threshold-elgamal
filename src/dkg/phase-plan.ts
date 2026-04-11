import type {
    ProtocolMessageType,
    PhaseCheckpointPayload,
} from '../protocol/types.js';
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
    'key-derivation-confirmation': 4,
    'ballot-submission': null,
    'ballot-close': null,
    'decryption-share': null,
    'tally-publication': null,
};

export const expectedDkgPhase = (
    messageType: ProtocolMessageType,
    payload?: PhaseCheckpointPayload,
): number | null =>
    messageType === 'phase-checkpoint'
        ? (payload?.checkpointPhase ?? null)
        : GJKR_PHASE_PLAN[messageType];
