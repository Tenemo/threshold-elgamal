// limit of Crypto.getRandomValues()
// https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
const MAX_BYTES = 65536;

// Node supports requesting up to this number of bytes
// https://github.com/nodejs/node/blob/master/lib/internal/crypto/random.js#L48
const MAX_UINT32 = 4294967295;

const randomBytes = (size: number): Buffer => {
    if (size > MAX_UINT32) {
        throw new RangeError('requested too many random bytes');
    }

    const bytes: Buffer = Buffer.allocUnsafe(size);

    // getRandomValues fails on IE if size == 0
    if (size > 0) {
        // this is the max bytes crypto.getRandomValues
        if (size > MAX_BYTES) {
            // can do at once see https://developer.mozilla.org/en-US/docs/Web/API/window.crypto.getRandomValues
            for (let generated = 0; generated < size; generated += MAX_BYTES) {
                // buffer.slice automatically checks if the end is past the end of
                // the buffer so we don't have to here
                crypto.getRandomValues(
                    bytes.slice(
                        generated,
                        Math.min(generated + MAX_BYTES, size),
                    ) as unknown as Uint8Array,
                );
            }
        } else {
            // Directly fill the buffer if within the limit
            crypto.getRandomValues(bytes as unknown as Uint8Array);
        }
    }

    return bytes;
};

const bytes2bigint = (bytes: Buffer): bigint => {
    let result = 0n;

    const n: number = bytes.length;

    // Read input in 8 byte slices. This is, on average and at the time
    // of writing, about 35x faster for large inputs than processing them
    // one byte at a time.
    if (n >= 8) {
        const view: DataView = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        );

        for (let i = 0, k = n & ~7; i < k; i += 8) {
            const x: bigint = view.getBigUint64(i, false);
            result = (result << 64n) + x;
        }
    }

    // Now mop up any remaining bytes.
    for (let i = n & ~7; i < n; i++) result = result * 256n + BigInt(bytes[i]);

    return result;
};

// Note: mutates the contents of |bytes|.
function maskBits(m: number, bytes: Buffer): void {
    // Mask off bits from the MSB that are > log2(bits).
    // |bytes| is treated as a big-endian bigint so byte 0 is the MSB.
    if (bytes.length > 0) bytes[0] &= m;
}

export const randomBigint = (bits: number): bigint => {
    if (bits < 0) throw new RangeError('bits < 0');

    const n: number = (bits >>> 3) + (bits & 7 ? 1 : 0); // Round up to next byte.
    const r: number = 8 * n - bits;
    const s: number = 8 - r;
    const m: number = (1 << s) - 1; // Bits to mask off from MSB.

    const bytes: Buffer = randomBytes(n);

    maskBits(m, bytes);

    return bytes2bigint(bytes);
};
