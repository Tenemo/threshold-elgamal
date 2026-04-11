import { assertFrozenHDerivationsMatch } from './internal/core-reproducibility.js';

const main = (): void => {
    assertFrozenHDerivationsMatch();

    console.log('h derivation matches the frozen constants for all suites.');
};

void main();
