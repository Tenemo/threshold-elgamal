export type CreateDeterministicSourceOptions = {
    readonly advanceBetweenCalls?: boolean;
    readonly postCallOffset?: number;
};

export const createDeterministicSource = (
    seed = 0,
    options: CreateDeterministicSourceOptions = {},
) => {
    let counter = seed & 0xff;
    const advanceBetweenCalls = options.advanceBetweenCalls ?? true;
    const postCallOffset = options.postCallOffset ?? 0;

    return (length: number): Uint8Array => {
        const bytes = new Uint8Array(length);
        for (let index = 0; index < length; index += 1) {
            bytes[index] = (counter + index) & 0xff;
        }

        if (advanceBetweenCalls) {
            counter = (counter + length + postCallOffset) & 0xff;
        }

        return bytes;
    };
};
