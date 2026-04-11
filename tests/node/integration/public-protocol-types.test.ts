import {
    type ProtocolMessageType,
    type ProtocolPayload,
} from 'threshold-elgamal';

import { describe, expect, it } from 'vitest';

type MessageTypeIsPublic<TMessageType extends string> =
    Extract<ProtocolMessageType, TMessageType> extends never ? false : true;

type PayloadShapeIsPublic<TMessageType extends string> =
    Extract<
        ProtocolPayload,
        { readonly messageType: TMessageType }
    > extends never
        ? false
        : true;

describe('public protocol types', () => {
    it('exclude unsupported message variants from the shipped public union', () => {
        const feldmanShareRevealIsPublic: MessageTypeIsPublic<'feldman-share-reveal'> = false;
        const ceremonyRestartIsPublic: MessageTypeIsPublic<'ceremony-restart'> = false;

        expect(feldmanShareRevealIsPublic).toBe(false);
        expect(ceremonyRestartIsPublic).toBe(false);
    });

    it('exclude unsupported payload shapes from the shipped public union', () => {
        const feldmanShareRevealPayloadIsPublic: PayloadShapeIsPublic<'feldman-share-reveal'> = false;
        const ceremonyRestartPayloadIsPublic: PayloadShapeIsPublic<'ceremony-restart'> = false;

        expect(feldmanShareRevealPayloadIsPublic).toBe(false);
        expect(ceremonyRestartPayloadIsPublic).toBe(false);
    });
});
