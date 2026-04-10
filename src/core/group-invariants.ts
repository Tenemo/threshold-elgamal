import { UnsupportedSuiteError } from './errors.js';
import { RISTRETTO_GROUP } from './groups.js';
import type { CryptoGroup } from './types.js';

const sameCanonicalRistrettoGroup = (group: CryptoGroup): boolean =>
    group.name === RISTRETTO_GROUP.name &&
    group.byteLength === RISTRETTO_GROUP.byteLength &&
    group.scalarByteLength === RISTRETTO_GROUP.scalarByteLength &&
    group.q === RISTRETTO_GROUP.q &&
    group.g === RISTRETTO_GROUP.g &&
    group.h === RISTRETTO_GROUP.h &&
    group.securityEstimate === RISTRETTO_GROUP.securityEstimate;

export const assertCanonicalRistrettoGroup = (
    group: CryptoGroup,
    label = 'Group',
): void => {
    if (!sameCanonicalRistrettoGroup(group)) {
        throw new UnsupportedSuiteError(
            `${label} must match the shipped canonical ristretto255 group definition`,
        );
    }
};
