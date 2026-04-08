import { deriveH, getGroup, listGroups } from './groups.js';

export type FrozenHDerivationCheck = {
    readonly derived: bigint;
    readonly frozen: bigint;
    readonly groupName: string;
    readonly matches: boolean;
};

export const verifyFrozenHDerivations = async (): Promise<
    readonly FrozenHDerivationCheck[]
> =>
    Promise.all(
        listGroups().map(async (group) => {
            const derived = await deriveH(group.name);
            const frozen = getGroup(group.name).h;

            return {
                groupName: group.name,
                derived,
                frozen,
                matches: derived === frozen,
            };
        }),
    );

export const assertFrozenHDerivationsMatch = async (): Promise<void> => {
    const mismatches = (await verifyFrozenHDerivations()).filter(
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
