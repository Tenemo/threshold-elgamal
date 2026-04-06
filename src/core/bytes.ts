export const bytesToHex = (bytes: Uint8Array): string => {
    let hex = '';
    for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, '0');
    }

    return hex;
};

export const bytesToBigInt = (bytes: Uint8Array): bigint => {
    if (bytes.length === 0) {
        return 0n;
    }

    const hex = bytesToHex(bytes);
    return BigInt(`0x${hex}`);
};
