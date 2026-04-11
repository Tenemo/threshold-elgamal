import { deriveH, getGroup, listGroups } from '#src/core/groups';

type FrozenHDerivationCheck = {
    readonly derived: string;
    readonly frozen: string;
    readonly groupName: string;
    readonly matches: boolean;
};

const verifyFrozenHDerivations = (): readonly FrozenHDerivationCheck[] =>
    listGroups().map((group) => {
        const derived = deriveH();
        const frozen = getGroup(group.name).h;

        return {
            groupName: group.name,
            derived,
            frozen,
            matches: derived === frozen,
        };
    });

const assertFrozenHDerivationsMatch = (): void => {
    const mismatches = verifyFrozenHDerivations().filter(
        (result) => !result.matches,
    );

    if (mismatches.length > 0) {
        const details = mismatches
            .map(
                (result) =>
                    `${result.groupName}: derived ${result.derived} != frozen ${result.frozen}`,
            )
            .join('; ');

        throw new Error(
            `Derived h does not match the frozen constant for: ${details}`,
        );
    }
};

const main = (): void => {
    assertFrozenHDerivationsMatch();

    console.log('h derivation matches the frozen constants for all suites.');
};

void main();
