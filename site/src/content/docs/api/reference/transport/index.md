---
title: "transport"
description: "Generated reference page for the `transport` export surface."
editUrl: false
sidebar:
  order: 7
---
[**threshold-elgamal**](../)

***

[threshold-elgamal](../modules/) / transport

# transport

Authentication, transport key agreement, envelope, and complaint helpers.

This module contains the public transport-layer primitives used by the
current protocol surface.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [ComplaintResolution](type-aliases/ComplaintResolution/) | Dealer-challenge complaint resolution outcome. |
| [EncryptedEnvelope](type-aliases/EncryptedEnvelope/) | Sender-ephemeral encrypted transport envelope. |
| [EnvelopeContext](type-aliases/EnvelopeContext/) | Context bound into HKDF info and AEAD associated data for envelopes. |
| [GenerateAuthKeyPairOptions](type-aliases/GenerateAuthKeyPairOptions/) | Options controlling authentication-key generation. |
| [GenerateTransportKeyPairOptions](type-aliases/GenerateTransportKeyPairOptions/) | Options controlling transport-key generation. |
| [KeyAgreementSuite](type-aliases/KeyAgreementSuite/) | Supported transport key-agreement suites. |
| [TransportKeyPair](type-aliases/TransportKeyPair/) | Transport key pair tagged with its negotiated suite. |

## Functions

| Function | Description |
| ------ | ------ |
| [assertNonZeroSharedSecret](functions/assertNonZeroSharedSecret/) | Rejects all-zero key-agreement secrets. |
| [decryptEnvelope](functions/decryptEnvelope/) | Decrypts an authenticated envelope with the recipient transport private key. |
| [deriveTransportPublicKey](functions/deriveTransportPublicKey/) | Re-derives the raw public key from a transport private key. |
| [deriveTransportSharedSecret](functions/deriveTransportSharedSecret/) | Derives a raw shared secret for the selected transport suite. |
| [encryptEnvelope](functions/encryptEnvelope/) | Encrypts a payload into a sender-ephemeral authenticated envelope. |
| [exportAuthPublicKey](functions/exportAuthPublicKey/) | Exports an authentication public key as SPKI hex. |
| [exportTransportPublicKey](functions/exportTransportPublicKey/) | Exports a transport public key as raw lowercase hexadecimal bytes. |
| [generateAuthKeyPair](functions/generateAuthKeyPair/) | Generates a fresh per-ceremony ECDSA P-256 authentication key pair. |
| [generateTransportKeyPair](functions/generateTransportKeyPair/) | Generates a transport key pair for the requested or preferred supported suite. |
| [importAuthPublicKey](functions/importAuthPublicKey/) | Imports an authentication public key from SPKI hex. |
| [importTransportPublicKey](functions/importTransportPublicKey/) | Imports a transport public key from raw hexadecimal bytes. |
| [isX25519Supported](functions/isX25519Supported/) | Returns whether the current runtime supports X25519 via Web Crypto. |
| [resolveDealerChallenge](functions/resolveDealerChallenge/) | Resolves a dealer challenge by revealing the sender-ephemeral private key. |
| [resolveDealerChallengeFromPublicKey](functions/resolveDealerChallengeFromPublicKey/) | Resolves a dealer challenge using only public transcript material plus the dealer-revealed sender-ephemeral private key. |
| [resolveTransportSuite](functions/resolveTransportSuite/) | Resolves the preferred key-agreement suite with X25519 fallback to P-256. |
| [signPayloadBytes](functions/signPayloadBytes/) | Signs canonical payload bytes with an authentication private key. |
| [verifyComplaintPrecondition](functions/verifyComplaintPrecondition/) | Verifies that the local recipient transport key still matches the registered public key before filing a transport complaint. |
| [verifyLocalTransportKey](functions/verifyLocalTransportKey/) | Verifies that a local transport private key matches the registered public key. |
| [verifyPayloadSignature](functions/verifyPayloadSignature/) | Verifies canonical payload bytes against a P-256 authentication signature. |
