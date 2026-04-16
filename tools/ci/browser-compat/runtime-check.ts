import {
    createElectionManifest,
    createManifestPublicationPayload,
    decryptEnvelope,
    deriveSessionId,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    hashElectionManifest,
    hashRosterEntries,
} from '../../../src/index';

type BrowserCryptoCompatibilityReport = {
    readonly directWebCrypto: {
        readonly ed25519: {
            readonly importedVerification: true;
            readonly publicKeyAlgorithm: string;
            readonly signatureLength: number;
            readonly spkiLength: number;
        };
        readonly x25519: {
            readonly importedSharedSecretMatches: true;
            readonly publicKeyAlgorithm: string;
            readonly publicKeyLength: number;
            readonly sharedSecretLength: number;
        };
    };
    readonly library: {
        readonly authAlgorithm: string;
        readonly messageType: string;
        readonly transportSuite: string;
        readonly decryptedPlaintext: string;
        readonly envelopeSuite: string;
    };
    readonly runtime: {
        readonly language: string;
        readonly userAgent: string;
        readonly viewport: {
            readonly height: number;
            readonly width: number;
        };
    };
};

type BrowserCryptoCompatibilityWindow = Window &
    typeof globalThis & {
        runBrowserCryptoCompatCheck?: () => Promise<BrowserCryptoCompatibilityReport>;
    };

const assert: (condition: unknown, message: string) => asserts condition = (
    condition: unknown,
    message: string,
): asserts condition => {
    if (!condition) {
        throw new Error(message);
    }
};

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean =>
    left.length === right.length &&
    left.every((value, index) => value === right[index]);

const isAllZeroBytes = (bytes: Uint8Array): boolean =>
    bytes.every((value) => value === 0);

const formatProbeError = (error: unknown): string =>
    error instanceof Error ? `${error.name}: ${error.message}` : String(error);

const runProbe = async <T>(
    label: string,
    probe: () => Promise<T>,
): Promise<T> => {
    try {
        return await probe();
    } catch (error) {
        const wrappedError = new Error(
            `${label} failed: ${formatProbeError(error)}`,
        ) as Error & {
            cause?: unknown;
        };

        wrappedError.cause = error;
        throw wrappedError;
    }
};

const runDirectEd25519Probe = async (): Promise<
    BrowserCryptoCompatibilityReport['directWebCrypto']['ed25519']
> => {
    const payload = new TextEncoder().encode('browser-crypto-compat-ed25519');
    const keyPair = await globalThis.crypto.subtle.generateKey(
        {
            name: 'Ed25519',
        },
        true,
        ['sign', 'verify'],
    );
    const signature = new Uint8Array(
        await globalThis.crypto.subtle.sign(
            'Ed25519',
            keyPair.privateKey,
            payload,
        ),
    );
    const spkiBytes = new Uint8Array(
        await globalThis.crypto.subtle.exportKey('spki', keyPair.publicKey),
    );
    const importedPublicKey = await globalThis.crypto.subtle.importKey(
        'spki',
        spkiBytes,
        {
            name: 'Ed25519',
        },
        true,
        ['verify'],
    );
    const importedVerification = await globalThis.crypto.subtle.verify(
        'Ed25519',
        importedPublicKey,
        signature,
        payload,
    );

    assert(
        importedVerification,
        'Direct Ed25519 verify() failed after SPKI import',
    );

    return {
        importedVerification: true,
        publicKeyAlgorithm: keyPair.publicKey.algorithm.name,
        signatureLength: signature.length,
        spkiLength: spkiBytes.length,
    };
};

const runDirectX25519Probe = async (): Promise<
    BrowserCryptoCompatibilityReport['directWebCrypto']['x25519']
> => {
    const localKeyPair = await globalThis.crypto.subtle.generateKey(
        {
            name: 'X25519',
        },
        true,
        ['deriveBits'],
    );
    const remoteKeyPair = await globalThis.crypto.subtle.generateKey(
        {
            name: 'X25519',
        },
        true,
        ['deriveBits'],
    );
    const rawPublicKey = new Uint8Array(
        await globalThis.crypto.subtle.exportKey('raw', localKeyPair.publicKey),
    );
    const importedPublicKey = await globalThis.crypto.subtle.importKey(
        'raw',
        rawPublicKey,
        {
            name: 'X25519',
        },
        true,
        [],
    );
    const localSharedSecret = new Uint8Array(
        await globalThis.crypto.subtle.deriveBits(
            {
                name: 'X25519',
                public: remoteKeyPair.publicKey,
            },
            localKeyPair.privateKey,
            256,
        ),
    );
    const remoteSharedSecret = new Uint8Array(
        await globalThis.crypto.subtle.deriveBits(
            {
                name: 'X25519',
                public: localKeyPair.publicKey,
            },
            remoteKeyPair.privateKey,
            256,
        ),
    );
    const importedSharedSecret = new Uint8Array(
        await globalThis.crypto.subtle.deriveBits(
            {
                name: 'X25519',
                public: importedPublicKey,
            },
            remoteKeyPair.privateKey,
            256,
        ),
    );

    assert(
        equalBytes(localSharedSecret, remoteSharedSecret),
        'Direct X25519 shared secrets did not match',
    );
    assert(
        equalBytes(remoteSharedSecret, importedSharedSecret),
        'Direct X25519 imported public key changed the shared secret',
    );
    assert(
        !isAllZeroBytes(localSharedSecret),
        'Direct X25519 shared secret unexpectedly collapsed to all zero bytes',
    );

    return {
        importedSharedSecretMatches: true,
        publicKeyAlgorithm: localKeyPair.publicKey.algorithm.name,
        publicKeyLength: rawPublicKey.length,
        sharedSecretLength: localSharedSecret.length,
    };
};

const runLibraryProbe = async (): Promise<
    BrowserCryptoCompatibilityReport['library']
> => {
    const auth = await generateAuthKeyPair({ extractable: true });
    const peerAuth = await generateAuthKeyPair({ extractable: true });
    const senderTransport = await generateTransportKeyPair({
        extractable: true,
    });
    const recipientTransport = await generateTransportKeyPair({
        extractable: true,
    });
    const authPublicKey = await exportAuthPublicKey(auth.publicKey);
    const peerAuthPublicKey = await exportAuthPublicKey(peerAuth.publicKey);
    const senderTransportPublicKey = await exportTransportPublicKey(
        senderTransport.publicKey,
    );
    const recipientTransportPublicKey = await exportTransportPublicKey(
        recipientTransport.publicKey,
    );
    const rosterHash = await hashRosterEntries([
        {
            participantIndex: 1,
            authPublicKey,
            transportPublicKey: senderTransportPublicKey,
        },
        {
            participantIndex: 2,
            authPublicKey: peerAuthPublicKey,
            transportPublicKey: recipientTransportPublicKey,
        },
    ]);
    const manifest = createElectionManifest({
        rosterHash,
        optionList: ['Option A', 'Option B'],
        scoreRange: { min: 0, max: 5 },
    });
    const manifestHash = await hashElectionManifest(manifest);
    const sessionId = await deriveSessionId(
        manifestHash,
        rosterHash,
        'browser-compat-nonce',
        '2026-04-12T12:00:00Z',
    );
    const signedManifest = await createManifestPublicationPayload(
        auth.privateKey,
        {
            manifest,
            manifestHash,
            participantIndex: 1,
            sessionId,
        },
    );
    const plaintext = new TextEncoder().encode('browser-compat-envelope');
    const encrypted = await encryptEnvelope(
        plaintext,
        recipientTransportPublicKey,
        {
            sessionId,
            rosterHash,
            phase: 1,
            dealerIndex: 1,
            recipientIndex: 2,
            envelopeId: 'browser-compat-1-2',
            payloadType: 'encrypted-dual-share',
            protocolVersion: 'v1',
            suite: 'X25519',
        },
    );
    const decrypted = await decryptEnvelope(
        encrypted.envelope,
        recipientTransport.privateKey,
    );
    const decryptedPlaintext = new TextDecoder().decode(decrypted);

    assert(
        decryptedPlaintext === 'browser-compat-envelope',
        'Library envelope round-trip failed',
    );

    return {
        authAlgorithm: auth.publicKey.algorithm.name,
        messageType: signedManifest.payload.messageType,
        transportSuite: senderTransport.suite,
        decryptedPlaintext,
        envelopeSuite: encrypted.envelope.suite,
    };
};

export const runBrowserCryptoCompatCheck =
    async (): Promise<BrowserCryptoCompatibilityReport> => {
        assert(
            typeof globalThis.crypto?.subtle !== 'undefined',
            'crypto.subtle is required for browser compatibility checks',
        );
        assert(
            typeof globalThis.crypto.getRandomValues === 'function',
            'crypto.getRandomValues is required for browser compatibility checks',
        );
        assert(
            typeof navigator !== 'undefined',
            'navigator is required in browser mode',
        );

        const directWebCrypto = {
            ed25519: await runProbe(
                'Direct Web Crypto Ed25519 compatibility probe',
                runDirectEd25519Probe,
            ),
            x25519: await runProbe(
                'Direct Web Crypto X25519 compatibility probe',
                runDirectX25519Probe,
            ),
        };
        const library = await runProbe(
            'Public API browser compatibility probe',
            runLibraryProbe,
        );
        const viewport = {
            width: globalThis.innerWidth,
            height: globalThis.innerHeight,
        };

        assert(
            directWebCrypto.ed25519.publicKeyAlgorithm === 'Ed25519',
            `Expected Ed25519 public key algorithm, received ${directWebCrypto.ed25519.publicKeyAlgorithm}`,
        );
        assert(
            directWebCrypto.x25519.publicKeyAlgorithm === 'X25519',
            `Expected X25519 public key algorithm, received ${directWebCrypto.x25519.publicKeyAlgorithm}`,
        );
        assert(
            library.authAlgorithm === 'Ed25519',
            `Expected library auth algorithm Ed25519, received ${library.authAlgorithm}`,
        );
        assert(
            library.transportSuite === 'X25519',
            `Expected library transport suite X25519, received ${library.transportSuite}`,
        );
        assert(
            library.envelopeSuite === 'X25519',
            `Expected encrypted envelope suite X25519, received ${library.envelopeSuite}`,
        );
        assert(
            library.messageType === 'manifest-publication',
            `Expected manifest-publication payload, received ${library.messageType}`,
        );

        return {
            directWebCrypto,
            library,
            runtime: {
                language: navigator.language,
                userAgent: navigator.userAgent,
                viewport,
            },
        };
    };

(window as BrowserCryptoCompatibilityWindow).runBrowserCryptoCompatCheck =
    runBrowserCryptoCompatCheck;
