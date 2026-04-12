import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import {
    copyFile,
    mkdtemp,
    mkdir,
    readdir,
    rm,
    writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

type PackageManager = 'npm' | 'pnpm';

const resolvePackageManagerEntrypoint = (
    packageManager: PackageManager,
): string => {
    if (packageManager === 'pnpm') {
        const pnpmEntrypoint = process.env.npm_execpath;

        if (pnpmEntrypoint === undefined) {
            throw new Error('npm_execpath is required to run pnpm commands');
        }

        return pnpmEntrypoint;
    }

    const npmCliEntrypointCandidates = [
        join(
            dirname(process.execPath),
            'node_modules',
            'npm',
            'bin',
            'npm-cli.js',
        ),
        join(
            dirname(process.execPath),
            '..',
            'lib',
            'node_modules',
            'npm',
            'bin',
            'npm-cli.js',
        ),
        join(
            dirname(process.execPath),
            '..',
            'node_modules',
            'npm',
            'bin',
            'npm-cli.js',
        ),
    ];

    for (const npmCliEntrypointCandidate of npmCliEntrypointCandidates) {
        if (existsSync(npmCliEntrypointCandidate)) {
            return npmCliEntrypointCandidate;
        }
    }

    throw new Error(
        `Unable to locate the npm CLI entrypoint. Searched: ${npmCliEntrypointCandidates.join(', ')}`,
    );
};

const runPackageManager = (
    packageManager: PackageManager,
    args: readonly string[],
    cwd: string,
): void => {
    const packageManagerEntrypoint =
        resolvePackageManagerEntrypoint(packageManager);
    const commandArgs = [packageManagerEntrypoint, ...args];
    const commandDescription = [process.execPath, ...commandArgs].join(' ');
    const result = spawnSync(process.execPath, commandArgs, {
        cwd,
        env: process.env,
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
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
        const stdout = result.stdout?.trim();
        const stderr = result.stderr?.trim();
        const formattedOutput =
            stdout !== '' || stderr !== ''
                ? `\n${[stdout, stderr].filter(Boolean).join('\n')}`
                : '';
        throw new Error(
            `Command exited with status ${result.status ?? 'null'}: ${commandDescription}${formattedOutput}`,
        );
    }
};

const installTarball = (
    packageManager: PackageManager,
    tarballPath: string,
    consumerDirectory: string,
): void => {
    const installArgs =
        packageManager === 'pnpm'
            ? ['add', '--ignore-scripts', '--silent', tarballPath]
            : ['install', '--ignore-scripts', '--silent', tarballPath];

    runPackageManager(packageManager, installArgs, consumerDirectory);
};

const runConsumerSmoke = async (
    tempRoot: string,
    tarballPath: string,
    packageManager: PackageManager,
): Promise<void> => {
    const consumerDirectory = join(tempRoot, `consumer-${packageManager}`);

    await mkdir(consumerDirectory, { recursive: true });
    await writeFile(
        join(consumerDirectory, 'package.json'),
        JSON.stringify(
            {
                name: `threshold-elgamal-smoke-consumer-${packageManager}`,
                private: true,
                type: 'module',
            },
            null,
            2,
        ),
        'utf8',
    );
    await copyFile(
        join(repoRoot, 'tools/ci/packed-package-smoke.mjs'),
        join(consumerDirectory, 'smoke.mjs'),
    );

    installTarball(packageManager, tarballPath, consumerDirectory);

    const commandArgs = ['smoke.mjs'];
    const commandDescription = [process.execPath, ...commandArgs].join(' ');
    const result = spawnSync(process.execPath, commandArgs, {
        cwd: consumerDirectory,
        env: process.env,
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
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
        const stdout = result.stdout?.trim();
        const stderr = result.stderr?.trim();
        const formattedOutput =
            stdout !== '' || stderr !== ''
                ? `\n${[stdout, stderr].filter(Boolean).join('\n')}`
                : '';
        throw new Error(
            `Smoke entrypoint exited with status ${result.status ?? 'null'} for ${packageManager}: ${commandDescription}${formattedOutput}`,
        );
    }
};

const main = async (): Promise<void> => {
    const tempRoot = await mkdtemp(
        join(tmpdir(), 'threshold-elgamal-packed-package-'),
    );
    const packDirectory = join(tempRoot, 'pack');

    try {
        await mkdir(packDirectory, { recursive: true });

        runPackageManager(
            'pnpm',
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

        await runConsumerSmoke(tempRoot, tarballPath, 'pnpm');
        await runConsumerSmoke(tempRoot, tarballPath, 'npm');

        console.log(
            'Packed package smoke test passed for pnpm and npm consumers.',
        );
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
};

void main();
