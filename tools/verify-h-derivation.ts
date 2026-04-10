import { assertFrozenHDerivationsMatch } from '../dev-support/core-reproducibility.js';

const main = (): void => {
    assertFrozenHDerivationsMatch();

    console.log('h derivation matches the frozen constants for all suites.');
};

void main();
