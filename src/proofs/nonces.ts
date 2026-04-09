import { bytesToBigInt } from '../core/bytes.js';
import {
    modQ,
    randomBytes,
    sha256,
    type CryptoGroup,
    type RandomBytesSource,
} from '../core/index.js';
import {
    bigintToFixedBytes,
    concatBytes,
    domainSeparator,
} from '../serialize/index.js';

const bitLength = (value: bigint): number =>
    value === 0n ? 0 : value.toString(2).length;

const encodeCounter = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, value, false);
    return bytes;
};

const expandHash = async (
    input: Uint8Array,
    outputLength: number,
): Promise<Uint8Array> => {
    const chunks: Uint8Array[] = [];
    let produced = 0;
    let counter = 0;

    while (produced < outputLength) {
        const chunk = await sha256(concatBytes(encodeCounter(counter), input));
        chunks.push(chunk);
        produced += chunk.length;
        counter += 1;
    }

    return concatBytes(...chunks).subarray(0, outputLength);
};

/**
 * Generates a hedged nonce with domain-separated wide reduction.
 *
 * @param secret Secret scalar used to hedge the nonce derivation.
 * @param context Deterministic context bytes for the proof statement.
 * @param group Resolved group definition.
 * @param randomSource Optional random source used for deterministic tests.
 * @returns A nonce reduced modulo `q`.
 */
export const hedgedNonce = async (
    secret: bigint,
    context: Uint8Array,
    group: CryptoGroup,
    randomSource?: RandomBytesSource,
): Promise<bigint> => {
    const randomPart = randomBytes(32, randomSource);
    const secretBytes = bigintToFixedBytes(secret, group.byteLength);
    const outputBits = bitLength(group.q) + 128;
    const outputBytes = Math.ceil(outputBits / 8);
    const seed = concatBytes(
        domainSeparator('threshold-elgamal-v1/nonce'),
        secretBytes,
        randomPart,
        context,
    );

    return modQ(bytesToBigInt(await expandHash(seed, outputBytes)), group.q);
};
