import { writeFile } from 'node:fs/promises';

import { generateThresholdVectorRecord } from './internal/threshold-reproducibility.js';

const bigintReplacer = (_key: string, value: unknown): unknown =>
    typeof value === 'bigint' ? value.toString() : value;

const main = async (): Promise<void> => {
    const payload = generateThresholdVectorRecord({
        groupName: 'ristretto255',
        polynomial: [12345n, 67890n, 13579n],
        participantCount: 5,
        message: 13n,
        bound: 20n,
        randomness: 4100n,
        subsetIndices: [1, 3, 5],
    });

    await writeFile(
        new URL('../test-vectors/threshold.json', import.meta.url),
        `${JSON.stringify(payload, bigintReplacer, 2)}\n`,
        'utf8',
    );

    console.log('Generated threshold test vectors.');
};

void main();
