import { InvalidScalarError } from '../core/index.js';
import {
    decodePoint,
    encodePoint,
    pointAdd,
    pointSubtract,
    pointMultiply,
} from '../core/ristretto.js';

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

/**
 * Solves a bounded discrete logarithm with the baby-step giant-step method.
 */
export const babyStepGiantStep = (
    target: string,
    base: string,
    bound: bigint,
): bigint | null => {
    if (bound < 0n) {
        throw new InvalidScalarError(
            'Discrete log search bound must be non-negative',
        );
    }

    const targetPoint = decodePoint(target, 'Discrete-log target');
    if (targetPoint.is0()) {
        return 0n;
    }

    const basePoint = decodePoint(base, 'Discrete-log base');
    const stepSize = integerSquareRootCeil(bound + 1n);
    const babySteps = new Map<string, bigint>();
    let babyStep = basePoint.subtract(basePoint);
    let exponent = 0n;

    while (exponent < stepSize) {
        babySteps.set(encodePoint(babyStep), exponent);
        babyStep = pointAdd(babyStep, basePoint);
        exponent += 1n;
    }

    const giantFactor = pointMultiply(basePoint, stepSize);
    let giantStep = targetPoint;
    let giantIndex = 0n;

    while (giantIndex <= stepSize) {
        const babyIndex = babySteps.get(encodePoint(giantStep));
        if (babyIndex !== undefined) {
            const discreteLog = giantIndex * stepSize + babyIndex;
            if (discreteLog <= bound) {
                return discreteLog;
            }
        }

        giantStep = pointSubtract(giantStep, giantFactor);
        giantIndex += 1n;
    }

    return null;
};
