import { InvalidScalarError, PlaintextDomainError } from './errors.js';

export const assertAdditiveBound = (bound: bigint, q: bigint): void => {
    if (bound < 0n || bound >= q) {
        throw new InvalidScalarError(
            'Additive plaintext bound must be in the range 0..q-1',
        );
    }
};

export const assertAdditivePlaintext = (
    value: bigint,
    bound: bigint,
    q: bigint,
): void => {
    assertAdditiveBound(bound, q);

    if (value < 0n || value > bound) {
        throw new PlaintextDomainError(
            `Additive mode requires plaintext values in the range 0..${bound}`,
        );
    }
};
