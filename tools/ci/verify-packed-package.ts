import { spawnSync } from 'node:child_process';
import {
    copyFile,
    mkdtemp,
    mkdir,
    readdir,
    rm,
    writeFile,
} from 'node:fs/promises';
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
        await copyFile(
            join(repoRoot, 'tools/ci/packed-package-smoke-template.txt'),
            join(consumerDirectory, 'smoke.mjs'),
        );

        runPackageManager(
            ['add', '--ignore-scripts', '--silent', tarballPath],
            consumerDirectory,
        );

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
                `Smoke entrypoint exited with status ${result.status ?? 'null'}: ${commandDescription}${formattedOutput}`,
            );
        }

        console.log('Packed package smoke test passed.');
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
};

void main();
