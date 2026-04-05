import type { CryptoGroup, GroupName, PrimeBits } from '../core/types.js';

export type ElgamalGroupInput = CryptoGroup | GroupName | PrimeBits;

export type ElgamalKeyPair = {
    readonly publicKey: bigint;
    readonly privateKey: bigint;
};

export type ElgamalParameters = ElgamalKeyPair & {
    readonly group: CryptoGroup;
};

export type ElgamalCiphertext = {
    readonly c1: bigint;
    readonly c2: bigint;
};
