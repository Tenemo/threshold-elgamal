/** Supported transport key-agreement suites. */
export type KeyAgreementSuite = 'X25519' | 'P-256';

/** Transport key pair tagged with its negotiated suite. */
export type TransportKeyPair = {
    readonly suite: KeyAgreementSuite;
    readonly privateKey: CryptoKey;
    readonly publicKey: CryptoKey;
};

/** Context bound into HKDF info and AEAD associated data for envelopes. */
export type EnvelopeContext = {
    readonly sessionId: string;
    readonly rosterHash: string;
    readonly phase: number;
    readonly dealerIndex: number;
    readonly recipientIndex: number;
    readonly envelopeId: string;
    readonly payloadType: string;
    readonly protocolVersion: string;
    readonly suite: KeyAgreementSuite;
};

/** Sender-ephemeral encrypted transport envelope. */
export type EncryptedEnvelope = EnvelopeContext & {
    readonly ephemeralPublicKey: string;
    readonly iv: string;
    readonly ciphertext: string;
};

/** Dealer-challenge complaint resolution outcome. */
export type ComplaintResolution = {
    readonly valid: boolean;
    readonly fault: 'dealer' | 'complainant';
    readonly plaintext?: Uint8Array;
};
