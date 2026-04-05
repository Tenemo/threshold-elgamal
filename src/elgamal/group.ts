import { getGroup, type CryptoGroup } from '../core/index.js';

import type { ElgamalGroupInput } from './types.js';

export const resolveElgamalGroup = (
    group: ElgamalGroupInput | undefined,
): CryptoGroup => {
    if (group === undefined) {
        return getGroup();
    }

    if (typeof group === 'object') {
        return group;
    }

    return getGroup(group);
};
