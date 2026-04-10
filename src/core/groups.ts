import { UnsupportedSuiteError } from './errors.js';
import { derivePedersenGenerator, RISTRETTO_BYTE_LENGTH } from './ristretto.js';
import type { CryptoGroup, GroupIdentifier } from './types.js';

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

const GROUPS = Object.freeze([RISTRETTO_GROUP]);

/** @internal Returns the immutable built-in Ristretto255 group definition. */
export const getGroup = (identifier: GroupIdentifier): CryptoGroup => {
    if (identifier !== RISTRETTO_GROUP.name) {
        throw new UnsupportedSuiteError(
            `Unsupported group: ${String(identifier)}`,
        );
    }

    return RISTRETTO_GROUP;
};

/** @internal Lists the immutable built-in group definitions. */
export const listGroups = (): readonly CryptoGroup[] => GROUPS;

/** Returns the canonical deterministic secondary generator encoding. */
export const deriveH = (): string => RISTRETTO_GROUP.h;
