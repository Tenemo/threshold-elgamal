import { assertFrozenHDerivationsMatch } from '../src/core/reproducibility.js';

const main = async (): Promise<void> => {
    await assertFrozenHDerivationsMatch();

    console.log('h derivation matches the frozen constants for all suites.');
};

void main();
