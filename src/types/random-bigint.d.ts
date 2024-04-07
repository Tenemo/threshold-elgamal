declare module 'random-bigint' {
    /**
     * Generates a random BigInt in the range 0..2**bits-1.
     * @param bits Number of bits.
     * @param cb Optional callback for asynchronous operation.
     */
    function random(
        bits: number,
        cb?: (err: Error | null, num: bigint) => void,
    ): bigint;

    export = random;
}
