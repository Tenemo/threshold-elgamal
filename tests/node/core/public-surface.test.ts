import { describe, expect, it } from 'vitest';

import * as publicApi from '#root';

describe('public package surface', () => {
    it('keeps internal audited-verification helpers out of the root export', () => {
        expect(publicApi).toHaveProperty('createDecryptionShare');
        expect(publicApi).toHaveProperty('verifyDKGTranscript');
        expect(publicApi).toHaveProperty('verifyElectionCeremony');
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
