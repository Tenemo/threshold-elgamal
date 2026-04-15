/**
 * Transport-layer types for authentication keys, X25519 envelopes, and the
 * metadata that binds encrypted share delivery to one ceremony slot.
 */
import type { Brand } from '../core/types';

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

/**
 * Context bound into HKDF info and AEAD associated data for envelopes.
 *
 * The same fields also identify the public complaint slot for one dealer to
 * recipient delivery.
 */
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

/**
 * Sender-ephemeral encrypted transport envelope.
 *
 * DKG share distribution publishes this object on the board so the recipient
 * can decrypt it and observers can later audit complaints against it.
 */
export type EncryptedEnvelope = EnvelopeContext & {
    readonly ephemeralPublicKey: EncodedTransportPublicKey;
    readonly iv: string;
    readonly ciphertext: string;
};
