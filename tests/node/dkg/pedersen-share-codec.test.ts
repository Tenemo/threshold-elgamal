import { describe, expect, it } from 'vitest';

import { InvalidPayloadError, RISTRETTO_GROUP } from '#src/core/public';
import {
    decodePedersenShareEnvelope,
    encodePedersenShareEnvelope,
} from '#src/dkg/public';

const envelopeByteLength = RISTRETTO_GROUP.scalarByteLength;

describe('Pedersen share envelope codec', () => {
    it('round-trips a canonical fixed-width envelope', () => {
        const share = {
            index: 2,
            secretValue: 0x1234n,
            blindingValue: 0x5678n,
        };
        const plaintext = new TextEncoder().encode(
            encodePedersenShareEnvelope(share, envelopeByteLength),
        );

        expect(
            decodePedersenShareEnvelope(
                plaintext,
                share.index,
                'Pedersen envelope',
            ),
        ).toEqual(share);
    });

    it('rejects non-canonical JSON encodings', () => {
        const nonCanonicalPlaintext = new TextEncoder().encode(
            JSON.stringify({
                index: 2,
                secretValue: '00'.repeat(envelopeByteLength),
                blindingValue: '11'.repeat(envelopeByteLength),
            }),
        );

        expect(() =>
            decodePedersenShareEnvelope(
                nonCanonicalPlaintext,
                2,
                'Pedersen envelope',
            ),
        ).toThrow(
            'Pedersen envelope plaintext must use canonical JSON encoding',
        );
    });

    it('rejects extra fields and non-object payloads', () => {
        const plaintextWithExtraField = new TextEncoder().encode(
            `{"blindingValue":"${'11'.repeat(envelopeByteLength)}","index":2,"secretValue":"${'00'.repeat(envelopeByteLength)}","unexpected":true}`,
        );

        expect(() =>
            decodePedersenShareEnvelope(
                plaintextWithExtraField,
                2,
                'Pedersen envelope',
            ),
        ).toThrow(
            'Pedersen envelope plaintext must contain only blindingValue, index, and secretValue',
        );
        expect(() =>
            decodePedersenShareEnvelope(
                new TextEncoder().encode('["not","an","object"]'),
                2,
                'Pedersen envelope',
            ),
        ).toThrow('Pedersen envelope plaintext must be a JSON object');
    });

    it('rejects non-canonical fixed-width hex fields', () => {
        expect(() =>
            decodePedersenShareEnvelope(
                new TextEncoder().encode(
                    `{"blindingValue":"${'11'.repeat(envelopeByteLength)}","index":2,"secretValue":"${'AA'.repeat(envelopeByteLength)}"}`,
                ),
                2,
                'Pedersen envelope',
            ),
        ).toThrow(
            `Pedersen envelope secret value must be a lowercase fixed-width hexadecimal string of length ${envelopeByteLength * 2}`,
        );
        expect(() =>
            decodePedersenShareEnvelope(
                new TextEncoder().encode(
                    `{"blindingValue":"${'11'.repeat(envelopeByteLength - 1)}","index":2,"secretValue":"${'00'.repeat(envelopeByteLength)}"}`,
                ),
                2,
                'Pedersen envelope',
            ),
        ).toThrow(
            `Pedersen envelope blinding value must be a lowercase fixed-width hexadecimal string of length ${envelopeByteLength * 2}`,
        );
    });

    it('rejects invalid utf-8 and participant-index mismatches', () => {
        expect(() =>
            decodePedersenShareEnvelope(
                Uint8Array.from([0xff]),
                2,
                'Pedersen envelope',
            ),
        ).toThrow('Pedersen envelope plaintext is not valid canonical JSON');
        expect(() =>
            decodePedersenShareEnvelope(
                new TextEncoder().encode(
                    `{"blindingValue":"${'11'.repeat(envelopeByteLength)}","index":3,"secretValue":"${'00'.repeat(envelopeByteLength)}"}`,
                ),
                2,
                'Pedersen envelope',
            ),
        ).toThrow(
            'Pedersen envelope share index mismatch: expected 2, received 3',
        );
    });

    it('throws InvalidPayloadError for malformed plaintexts', () => {
        expect(() =>
            decodePedersenShareEnvelope(
                new TextEncoder().encode('not-json'),
                1,
                'Pedersen envelope',
            ),
        ).toThrow(InvalidPayloadError);
    });
});
