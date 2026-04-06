export const bytesToBigInt = (bytes: Uint8Array): bigint => {
    if (bytes.length === 0) {
        return 0n;
    }

    let hex = '';
    for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, '0');
    }

    return BigInt(`0x${hex}`);
};
