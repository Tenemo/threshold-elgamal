import type { Brand } from '../core/types.js';

/** Canonical lowercase hexadecimal SPKI encoding for auth public keys. */
export type EncodedAuthPublicKey = Brand<string, 'EncodedAuthPublicKey'>;

/** Canonical lowercase hexadecimal raw encoding for transport public keys. */
export type EncodedTransportPublicKey = Brand<
    string,
    'EncodedTransportPublicKey'
>;

/** Canonical lowercase hexadecimal PKCS#8 encoding for transport private keys. */
export type EncodedTransportPrivateKey = Brand<
    string,
    'EncodedTransportPrivateKey'
>;

/** Transport key pair tagged with the fixed X25519 suite. */
export type TransportKeyPair = {
    readonly suite: 'X25519';
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
    readonly suite: 'X25519';
};

/** Sender-ephemeral encrypted transport envelope. */
export type EncryptedEnvelope = EnvelopeContext & {
    readonly ephemeralPublicKey: EncodedTransportPublicKey;
    readonly iv: string;
    readonly ciphertext: string;
};

/** Dealer-challenge complaint resolution outcome. */
export type ComplaintResolution = {
    readonly valid: boolean;
    readonly fault: 'dealer' | 'complainant';
    readonly plaintext?: Uint8Array;
};
