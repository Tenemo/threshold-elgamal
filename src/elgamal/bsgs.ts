import { InvalidScalarError, modInvP, modP, modPowP } from '../core/index.js';

const integerSquareRootCeil = (value: bigint): bigint => {
    if (value < 0n) {
        throw new InvalidScalarError(
            'Square root is undefined for negative bounds',
        );
    }

    if (value < 2n) {
        return value;
    }

    let low = 1n;
    let high = value;

    while (low <= high) {
        const middle = (low + high) / 2n;
        const square = middle * middle;

        if (square === value) {
            return middle;
        }

        if (square < value) {
            low = middle + 1n;
        } else {
            high = middle - 1n;
        }
    }

    return low;
};

export const babyStepGiantStep = (
    target: bigint,
    base: bigint,
    p: bigint,
    bound: bigint,
): bigint | null => {
    if (bound < 0n) {
        throw new InvalidScalarError(
            'Discrete log search bound must be non-negative',
        );
    }

    const stepSize = integerSquareRootCeil(bound + 1n);
    const babySteps = new Map<bigint, bigint>();
    let babyStep = 1n;
    let exponent = 0n;

    while (exponent < stepSize) {
        babySteps.set(babyStep, exponent);
        babyStep = modP(babyStep * base, p);
        exponent += 1n;
    }

    const factor = modInvP(modPowP(base, stepSize, p), p);
    let giantStep = modP(target, p);
    let giantIndex = 0n;

    while (giantIndex <= stepSize) {
        const babyIndex = babySteps.get(giantStep);
        if (babyIndex !== undefined) {
            const discreteLog = giantIndex * stepSize + babyIndex;
            if (discreteLog <= bound) {
                return discreteLog;
            }
        }

        giantStep = modP(giantStep * factor, p);
        giantIndex += 1n;
    }

    return null;
};
