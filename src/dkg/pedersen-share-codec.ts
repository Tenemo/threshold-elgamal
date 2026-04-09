import { InvalidPayloadError } from '../core/index.js';
import { canonicalizeJson } from '../protocol/canonical-json.js';
import { bigintToFixedHex, fixedHexToBigint } from '../serialize/index.js';
import type { PedersenShare } from '../vss/types.js';

type PedersenShareEnvelopeRecord = {
    readonly blindingValue: string;
    readonly index: number;
    readonly secretValue: string;
};

export const encodePedersenShareEnvelope = (
    share: PedersenShare,
    byteLength: number,
): string =>
    canonicalizeJson(
        {
            index: share.index,
            secretValue: bigintToFixedHex(share.secretValue, byteLength),
            blindingValue: bigintToFixedHex(share.blindingValue, byteLength),
        },
        {
            bigintByteLength: byteLength,
        },
    );

export const decodePedersenShareEnvelope = (
    plaintext: Uint8Array,
    expectedParticipantIndex: number,
    label: string,
): PedersenShare => {
    let parsed: PedersenShareEnvelopeRecord;

    try {
        parsed = JSON.parse(new TextDecoder().decode(plaintext)) as {
            readonly blindingValue: string;
            readonly index: number;
            readonly secretValue: string;
        };
    } catch {
        throw new InvalidPayloadError(
            `${label} plaintext is not valid canonical JSON`,
        );
    }

    if (parsed.index !== expectedParticipantIndex) {
        throw new InvalidPayloadError(
            `${label} share index mismatch: expected ${expectedParticipantIndex}, received ${parsed.index}`,
        );
    }

    return {
        index: parsed.index,
        secretValue: fixedHexToBigint(parsed.secretValue),
        blindingValue: fixedHexToBigint(parsed.blindingValue),
    };
};
