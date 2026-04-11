import { UnsupportedSuiteError } from './errors.js';
import { derivePedersenGenerator, RISTRETTO_BYTE_LENGTH } from './ristretto.js';
import type { CryptoGroup } from './types.js';

/** Immutable definition of the shipped Ristretto255 tally group. */
export const RISTRETTO_GROUP: CryptoGroup = Object.freeze({
    name: 'ristretto255',
    byteLength: RISTRETTO_BYTE_LENGTH,
    scalarByteLength: RISTRETTO_BYTE_LENGTH,
    q: BigInt(
        '0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed',
    ),
    g: 'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76' as CryptoGroup['g'],
    h: derivePedersenGenerator(),
    securityEstimate: 128,
});

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
    const normalizedLabel =
        label.length > 0 ? `${label[0].toLowerCase()}${label.slice(1)}` : label;

    if (!sameCanonicalRistrettoGroup(group)) {
        throw new UnsupportedSuiteError(
            `${normalizedLabel} must match the shipped canonical ristretto255 group definition`,
        );
    }
};
