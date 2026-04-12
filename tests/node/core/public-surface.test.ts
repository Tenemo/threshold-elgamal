import { describe, expect, it } from 'vitest';

import * as publicApi from '#root';

describe('public package surface', () => {
    it('exports the supported root verification and reveal helpers', () => {
        expect(publicApi).toHaveProperty('createDecryptionShare');
        expect(publicApi).toHaveProperty('verifyDKGTranscript');
        expect(publicApi).toHaveProperty('verifyElectionCeremony');
    });

    it('keeps internal audited-verification helpers out of the root export', () => {
        expect(publicApi).not.toHaveProperty(
            'verifyDKGTranscriptFromAuditedTranscript',
        );
        expect(publicApi).not.toHaveProperty(
            'verifyBallotSubmissionPayloadsByOptionFromAuditedPayloads',
        );
        expect(publicApi).not.toHaveProperty(
            'verifyDecryptionSharePayloadsByOptionFromAuditedPayloads',
        );
    });
});
