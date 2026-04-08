[**threshold-elgamal**](../index.md)

***

[threshold-elgamal](../modules.md) / transport

# transport

Authentication, transport key agreement, envelope, and complaint helpers.

This module contains the public transport-layer primitives used by the
current protocol surface.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [ComplaintResolution](type-aliases/ComplaintResolution.md) | Dealer-challenge complaint resolution outcome. |
| [EncryptedEnvelope](type-aliases/EncryptedEnvelope.md) | Sender-ephemeral encrypted transport envelope. |
| [EnvelopeContext](type-aliases/EnvelopeContext.md) | Context bound into HKDF info and AEAD associated data for envelopes. |
| [KeyAgreementSuite](type-aliases/KeyAgreementSuite.md) | Supported transport key-agreement suites. |
| [TransportKeyPair](type-aliases/TransportKeyPair.md) | Transport key pair tagged with its negotiated suite. |

## Functions

| Function | Description |
| ------ | ------ |
| [assertNonZeroSharedSecret](functions/assertNonZeroSharedSecret.md) | Rejects all-zero key-agreement secrets. |
| [decryptEnvelope](functions/decryptEnvelope.md) | Decrypts an authenticated envelope with the recipient transport private key. |
| [deriveTransportPublicKey](functions/deriveTransportPublicKey.md) | Re-derives the raw public key from a transport private key. |
| [deriveTransportSharedSecret](functions/deriveTransportSharedSecret.md) | Derives a raw shared secret for the selected transport suite. |
| [encryptEnvelope](functions/encryptEnvelope.md) | Encrypts a payload into a sender-ephemeral authenticated envelope. |
| [exportAuthPublicKey](functions/exportAuthPublicKey.md) | Exports an authentication public key as SPKI hex. |
| [exportTransportPrivateKey](functions/exportTransportPrivateKey.md) | Exports a transport private key as PKCS#8 lowercase hexadecimal bytes. |
| [exportTransportPublicKey](functions/exportTransportPublicKey.md) | Exports a transport public key as raw lowercase hexadecimal bytes. |
| [generateAuthKeyPair](functions/generateAuthKeyPair.md) | Generates a fresh per-ceremony ECDSA P-256 authentication key pair. |
| [generateTransportKeyPair](functions/generateTransportKeyPair.md) | Generates a transport key pair for the requested or preferred supported suite. |
| [importAuthPublicKey](functions/importAuthPublicKey.md) | Imports an authentication public key from SPKI hex. |
| [importTransportPrivateKey](functions/importTransportPrivateKey.md) | Imports a transport private key from PKCS#8 hexadecimal bytes. |
| [importTransportPublicKey](functions/importTransportPublicKey.md) | Imports a transport public key from raw hexadecimal bytes. |
| [isX25519Supported](functions/isX25519Supported.md) | Returns whether the current runtime supports X25519 via Web Crypto. |
| [resolveDealerChallenge](functions/resolveDealerChallenge.md) | Resolves a dealer challenge by revealing the sender-ephemeral private key. |
| [resolveTransportSuite](functions/resolveTransportSuite.md) | Resolves the preferred key-agreement suite with X25519 fallback to P-256. |
| [signPayloadBytes](functions/signPayloadBytes.md) | Signs canonical payload bytes with an authentication private key. |
| [verifyComplaintPrecondition](functions/verifyComplaintPrecondition.md) | Verifies that the local recipient transport key still matches the registered public key before filing a transport complaint. |
| [verifyLocalTransportKey](functions/verifyLocalTransportKey.md) | Verifies that a local transport private key matches the registered public key. |
| [verifyPayloadSignature](functions/verifyPayloadSignature.md) | Verifies canonical payload bytes against a P-256 authentication signature. |
