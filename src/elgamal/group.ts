import { getGroup, type CryptoGroup } from '../core/index.js';

import type { ElgamalGroupInput } from './types.js';

export const resolveElgamalGroup = (
    group: ElgamalGroupInput | undefined,
): CryptoGroup => getGroup(group ?? 2048);
