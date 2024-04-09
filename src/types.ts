export type EncryptedMessage = {
    c1: bigint;
    c2: bigint;
};

export type Parameters = {
    prime: bigint;
    generator: bigint;
    publicKey: bigint;
    privateKey: bigint;
};
