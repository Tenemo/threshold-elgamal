import { toBufferSource } from '../core/bytes.js';
import { getWebCrypto, hkdfSha256 } from '../core/index.js';
import { encodeForChallenge } from '../serialize/index.js';

import type { EnvelopeContext } from './types.js';

const envelopeKeySalt = (rosterHash: string): Uint8Array =>
    new TextEncoder().encode(rosterHash);

export const encodeEnvelopeContext = (context: EnvelopeContext): Uint8Array =>
    encodeForChallenge(
        context.sessionId,
        BigInt(context.phase),
        BigInt(context.dealerIndex),
        BigInt(context.recipientIndex),
        context.envelopeId,
        context.payloadType,
        context.protocolVersion,
        context.suite,
    );

export const deriveEnvelopeKey = async (
    sharedSecret: Uint8Array,
    context: EnvelopeContext,
    usages: KeyUsage[] = ['encrypt', 'decrypt'],
): Promise<CryptoKey> =>
    getWebCrypto().subtle.importKey(
        'raw',
        toBufferSource(
            await hkdfSha256(
                sharedSecret,
                envelopeKeySalt(context.rosterHash),
                encodeEnvelopeContext(context),
                32,
            ),
        ),
        'AES-GCM',
        false,
        usages,
    );
