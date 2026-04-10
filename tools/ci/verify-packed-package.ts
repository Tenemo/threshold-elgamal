import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const packageManagerEntrypoint = process.env.npm_execpath;
if (packageManagerEntrypoint === undefined) {
    throw new Error('npm_execpath is required to run package manager commands');
}

const runPackageManager = (args: readonly string[], cwd: string): void => {
    const commandArgs = [packageManagerEntrypoint, ...args];
    const commandDescription = [process.execPath, ...commandArgs].join(' ');
    const result = spawnSync(process.execPath, commandArgs, {
        cwd,
        stdio: 'inherit',
        env: process.env,
    });

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start command: ${commandDescription}: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(
            `Command terminated by signal ${result.signal}: ${commandDescription}`,
        );
    }
    if (result.status !== 0) {
        throw new Error(
            `Command exited with status ${result.status ?? 'null'}: ${commandDescription}`,
        );
    }
};

const main = async (): Promise<void> => {
    const tempRoot = await mkdtemp(
        join(tmpdir(), 'threshold-elgamal-packed-package-'),
    );
    const packDirectory = join(tempRoot, 'pack');
    const consumerDirectory = join(tempRoot, 'consumer');

    try {
        await mkdir(packDirectory, { recursive: true });
        await mkdir(consumerDirectory, { recursive: true });

        runPackageManager(
            ['pack', '--pack-destination', packDirectory],
            repoRoot,
        );

        const tarballs = (await readdir(packDirectory)).filter((entry) =>
            entry.endsWith('.tgz'),
        );
        if (tarballs.length !== 1) {
            throw new Error(
                `Expected exactly one packed tarball, received ${tarballs.length}`,
            );
        }

        const tarballPath = join(packDirectory, tarballs[0]);

        await writeFile(
            join(consumerDirectory, 'package.json'),
            JSON.stringify(
                {
                    name: 'threshold-elgamal-smoke-consumer',
                    private: true,
                    type: 'module',
                },
                null,
                2,
            ),
            'utf8',
        );
        await writeFile(
            join(consumerDirectory, 'smoke.mjs'),
            [
                "import { addEncryptedValues, createGjkrState, decryptAdditive, deriveH, encryptAdditive, generateParameters, hashProtocolPhaseSnapshot, resetBigintMathBackend, setBigintMathBackend } from 'threshold-elgamal';",
                '',
                'const { publicKey, privateKey } = generateParameters();',
                'const left = encryptAdditive(2n, publicKey, 10n);',
                'const right = encryptAdditive(3n, publicKey, 10n);',
                'const aggregate = addEncryptedValues(left, right);',
                'const tally = decryptAdditive(aggregate, privateKey, 20n);',
                'if (tally !== 5n) {',
                '  throw new Error(`Packed root import produced the wrong tally: ${tally.toString()}`);',
                '}',
                'if (deriveH().length !== 64) {',
                "  throw new Error('Packed core import failed deterministic H derivation');",
                '}',
                'const dkgState = createGjkrState({',
                "  sessionId: 'session-smoke',",
                "  manifestHash: 'manifest-smoke',",
                '  participantCount: 3,',
                '  threshold: 2,',
                '});',
                'if (dkgState.phase !== 0) {',
                "  throw new Error('Packed dkg import returned an unexpected initial phase');",
                '}',
                'const snapshotHash = await hashProtocolPhaseSnapshot([], 0);',
                'if (snapshotHash.length !== 64) {',
                "  throw new Error('Packed protocol import returned an invalid snapshot hash');",
                '}',
                'setBigintMathBackend();',
                'resetBigintMathBackend();',
                "console.log('Packed package smoke test passed.');",
                '',
            ].join('\n'),
            'utf8',
        );

        runPackageManager(['add', tarballPath], consumerDirectory);

        const commandArgs = ['smoke.mjs'];
        const commandDescription = [process.execPath, ...commandArgs].join(' ');
        const result = spawnSync(process.execPath, commandArgs, {
            cwd: consumerDirectory,
            stdio: 'inherit',
            env: process.env,
        });
        if (result.error !== undefined) {
            throw new Error(
                `Failed to start smoke entrypoint: ${commandDescription}: ${result.error.message}`,
            );
        }
        if (result.signal !== null) {
            throw new Error(
                `Smoke entrypoint terminated by signal ${result.signal}: ${commandDescription}`,
            );
        }
        if (result.status !== 0) {
            throw new Error(
                `Smoke entrypoint exited with status ${result.status ?? 'null'}: ${commandDescription}`,
            );
        }
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
};

void main();
