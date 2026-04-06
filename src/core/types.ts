export type Brand<T, TBrand extends string> = T & {
    readonly __brand: TBrand;
};

export type PrimeBits = 2048 | 3072 | 4096;
export type GroupName = 'ffdhe2048' | 'ffdhe3072' | 'ffdhe4096';

export type ScalarQ = Brand<bigint, 'ScalarQ'>;
export type GroupElement = Brand<bigint, 'GroupElement'>;
export type SubgroupElement = Brand<bigint, 'SubgroupElement'>;
// Roster indices stay as small 1-based numbers until threshold math converts
// them to bigint values for Z_q arithmetic.
export type ParticipantIndex = Brand<number, 'ParticipantIndex'>;
export type ValidatedPublicKey = Brand<SubgroupElement, 'ValidatedPublicKey'>;

export type CryptoGroup = {
    readonly name: GroupName;
    readonly bits: PrimeBits;
    readonly byteLength: number;
    readonly p: bigint;
    readonly q: bigint;
    readonly g: bigint;
    readonly h: bigint;
    readonly securityEstimate: number;
};

export type RandomBytesSource = (length: number) => Uint8Array;
