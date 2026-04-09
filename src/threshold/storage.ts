import { toBufferSource } from '../core/bytes.js';
import {
    assertPositiveParticipantIndex,
    getWebCrypto,
    randomBytes,
} from '../core/index.js';
import {
    bytesToHex,
    bigintToFixedBytes,
    encodeForChallenge,
    fixedHexToBigint,
    hexToBytes,
} from '../serialize/index.js';

import type { Share } from './types.js';

/** Wrapped share record suitable for durable local storage. */
export type WrappedShareRecord = {
    readonly index: number;
    readonly iv: string;
    readonly ciphertext: string;
};

const shareStorageAdditionalData = (index: number): Uint8Array =>
    encodeForChallenge('wrapped-share-index', BigInt(index));

/**
 * Returns whether the current runtime exposes the minimum capabilities required
 * for wrapped-share storage.
 *
 * @returns `true` when Web Crypto is available and IndexedDB exists.
 */
export const isShareStorageSupported = (): boolean =>
    typeof globalThis.indexedDB !== 'undefined' &&
    typeof globalThis.crypto?.subtle !== 'undefined';

/**
 * Generates a non-extractable AES-GCM key for share wrapping.
 *
 * @returns Non-extractable wrapping key.
 */
export const generateShareWrappingKey = async (): Promise<CryptoKey> =>
    getWebCrypto().subtle.generateKey(
        {
            name: 'AES-GCM',
            length: 256,
        },
        false,
        ['encrypt', 'decrypt'],
    );

/**
 * Wraps a Shamir share value for durable local storage.
 *
 * @param share Indexed Shamir share.
 * @param key Non-extractable wrapping key.
 * @param byteLength Fixed byte width used for the share scalar encoding.
 * @returns Wrapped share record with hex-encoded IV and ciphertext.
 */
export const wrapShareForStorage = async (
    share: Share,
    key: CryptoKey,
    byteLength: number,
): Promise<WrappedShareRecord> => {
    assertPositiveParticipantIndex(share.index);

    const iv = randomBytes(12);
    const ciphertext = new Uint8Array(
        await getWebCrypto().subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: toBufferSource(iv),
                additionalData: toBufferSource(
                    shareStorageAdditionalData(share.index),
                ),
            },
            key,
            toBufferSource(bigintToFixedBytes(share.value, byteLength)),
        ),
    );

    return {
        index: share.index,
        iv: bytesToHex(iv),
        ciphertext: bytesToHex(ciphertext),
    };
};

/**
 * Restores a wrapped Shamir share value from local storage.
 *
 * @param record Wrapped share record.
 * @param key Non-extractable wrapping key used during storage.
 * @returns Unwrapped indexed Shamir share.
 */
export const unwrapShareFromStorage = async (
    record: WrappedShareRecord,
    key: CryptoKey,
): Promise<Share> => {
    assertPositiveParticipantIndex(record.index);

    const plaintext = new Uint8Array(
        await getWebCrypto().subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: toBufferSource(hexToBytes(record.iv)),
                additionalData: toBufferSource(
                    shareStorageAdditionalData(record.index),
                ),
            },
            key,
            toBufferSource(hexToBytes(record.ciphertext)),
        ),
    );

    return {
        index: record.index,
        value: fixedHexToBigint(bytesToHex(plaintext)),
    };
};
