import { fileURLToPath } from 'node:url';

import type { BrowserContextOptions } from 'playwright';
import { chromium, devices, firefox, webkit } from 'playwright';
import { createServer } from 'vite';

type BrowserEngine = 'chromium' | 'firefox' | 'webkit';

type BrowserCryptoCompatibilityReport = {
    readonly directWebCrypto: {
        readonly ed25519: {
            readonly importedVerification: boolean;
            readonly publicKeyAlgorithm: string;
            readonly signatureLength: number;
            readonly spkiLength: number;
        };
        readonly x25519: {
            readonly importedSharedSecretMatches: boolean;
            readonly publicKeyAlgorithm: string;
            readonly publicKeyLength: number;
            readonly sharedSecretLength: number;
        };
    };
    readonly library: {
        readonly authAlgorithm: string;
        readonly decryptedPlaintext: string;
        readonly envelopeSuite: string;
        readonly messageType: string;
        readonly transportSuite: string;
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

type BrowserCompatibilityTarget = {
    readonly browser: BrowserEngine;
    readonly deviceName?: keyof typeof devices;
    readonly name: string;
    readonly platforms: readonly NodeJS.Platform[];
    readonly viewport?: BrowserContextOptions['viewport'];
};

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const compatibilityPagePath = '/tools/ci/browser-compat/index.html';

const targets = [
    {
        name: 'desktop-chromium',
        browser: 'chromium',
        platforms: ['darwin', 'linux', 'win32'],
        viewport: {
            width: 1440,
            height: 900,
        },
    },
    {
        name: 'desktop-firefox',
        browser: 'firefox',
        platforms: ['darwin', 'linux', 'win32'],
        viewport: {
            width: 1440,
            height: 900,
        },
    },
    {
        name: 'desktop-webkit',
        browser: 'webkit',
        platforms: ['darwin'],
        viewport: {
            width: 1440,
            height: 900,
        },
    },
    {
        name: 'mobile-android-chromium',
        browser: 'chromium',
        deviceName: 'Pixel 7',
        platforms: ['darwin', 'linux', 'win32'],
    },
    {
        name: 'mobile-ios-webkit',
        browser: 'webkit',
        deviceName: 'iPhone 15',
        platforms: ['darwin'],
    },
    {
        name: 'mobile-ipados-webkit',
        browser: 'webkit',
        deviceName: 'iPad (gen 11)',
        platforms: ['darwin'],
    },
] as const satisfies readonly BrowserCompatibilityTarget[];

const browserTypes = {
    chromium,
    firefox,
    webkit,
} as const;

const assert: (condition: unknown, message: string) => asserts condition = (
    condition: unknown,
    message: string,
): asserts condition => {
    if (!condition) {
        throw new Error(message);
    }
};

const formatError = (error: unknown): string =>
    error instanceof Error ? error.message : String(error);

const resolveTargets = (): readonly BrowserCompatibilityTarget[] => {
    const requestedTargets = process.argv
        .slice(2)
        .filter((argument) => argument.startsWith('--target='))
        .flatMap((argument) =>
            argument
                .slice('--target='.length)
                .split(',')
                .map((name) => name.trim())
                .filter((name) => name !== ''),
        );

    if (requestedTargets.length === 0) {
        return targets.filter((target) =>
            target.platforms.some((platform) => platform === process.platform),
        );
    }

    return requestedTargets.map((targetName) => {
        const target = targets.find(
            (candidate) => candidate.name === targetName,
        );

        if (target === undefined) {
            throw new Error(
                `Unknown browser compatibility target "${targetName}". Supported targets: ${targets.map((candidate) => candidate.name).join(', ')}`,
            );
        }

        return target;
    });
};

const createContextOptions = (
    target: BrowserCompatibilityTarget,
): BrowserContextOptions => {
    if (target.deviceName === undefined) {
        return {
            colorScheme: 'light',
            viewport: target.viewport,
        };
    }

    const deviceDescriptor = devices[target.deviceName];

    assert(
        deviceDescriptor !== undefined,
        `Unknown Playwright device descriptor "${target.deviceName}" for target "${target.name}". Available device names: ${Object.keys(devices).sort().join(', ')}`,
    );

    return {
        ...deviceDescriptor,
        colorScheme: 'light',
    };
};

const runTarget = async (
    baseUrl: string,
    target: BrowserCompatibilityTarget,
): Promise<void> => {
    const browser = await browserTypes[target.browser].launch({
        headless: true,
    });
    const context = await browser.newContext(createContextOptions(target));
    const page = await context.newPage();
    const pageErrors: string[] = [];

    page.on('pageerror', (error) => {
        pageErrors.push(error.message);
    });

    try {
        await page.goto(new URL(compatibilityPagePath, baseUrl).toString(), {
            waitUntil: 'networkidle',
        });
        await page.waitForFunction(
            () =>
                typeof (window as BrowserCryptoCompatibilityWindow)
                    .runBrowserCryptoCompatCheck === 'function',
        );

        const report = await page.evaluate(async () => {
            const compatibilityWindow =
                window as BrowserCryptoCompatibilityWindow;

            if (compatibilityWindow.runBrowserCryptoCompatCheck === undefined) {
                throw new Error(
                    'Browser compatibility probe was not registered',
                );
            }

            return compatibilityWindow.runBrowserCryptoCompatCheck();
        });

        assert(
            pageErrors.length === 0,
            `Unhandled browser page errors occurred:\n${pageErrors.join('\n')}`,
        );

        console.log(`[${target.name}] ${JSON.stringify(report)}`);
    } catch (error) {
        const userAgent = await page
            .evaluate(() => navigator.userAgent)
            .catch(() => 'unknown user agent');

        const wrappedError = new Error(
            `[${target.name}] browser compatibility probe failed for ${userAgent}: ${formatError(error)}`,
        ) as Error & {
            cause?: unknown;
        };

        wrappedError.cause = error;
        throw wrappedError;
    } finally {
        await context.close();
        await browser.close();
    }
};

const main = async (): Promise<void> => {
    const server = await createServer({
        logLevel: 'error',
        root: repoRoot,
        server: {
            host: '127.0.0.1',
            strictPort: false,
        },
    });

    await server.listen();

    try {
        const resolvedUrls =
            server.resolvedUrls?.local ?? server.resolvedUrls?.network;
        const baseUrl = resolvedUrls?.[0];

        assert(
            baseUrl !== undefined,
            'Unable to resolve the Vite dev server URL',
        );

        const selectedTargets = resolveTargets();

        for (const target of selectedTargets) {
            await runTarget(baseUrl, target);
        }

        console.log(
            `Verified browser Web Crypto compatibility for ${selectedTargets.length} targets.`,
        );
    } finally {
        await server.close();
    }
};

void main().catch((error: unknown) => {
    console.error(formatError(error));
    process.exitCode = 1;
});
