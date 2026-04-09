import { spawnSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRootUrl = new URL('../../', import.meta.url);
const repoRoot = fileURLToPath(repoRootUrl);
const testsRootUrl = new URL('../../tests/node/', import.meta.url);
const packageManagerEntrypoint = process.env.npm_execpath;

if (packageManagerEntrypoint === undefined) {
    throw new Error('npm_execpath is required to run package manager commands');
}

type SliceName = 'fast' | 'heavy';

const heavyTestFiles = new Set<string>([
    'tests/node/dkg/verification.test.ts',
    'tests/node/protocol/voting.test.ts',
]);

const toPosixPath = (value: string): string => value.replace(/\\/g, '/');

const collectTestFiles = async (directoryUrl: URL): Promise<string[]> => {
    const entries = await readdir(directoryUrl, {
        withFileTypes: true,
        recursive: true,
    });

    return entries
        .filter(
            (entry) =>
                entry.isFile() &&
                entry.parentPath !== undefined &&
                entry.name.endsWith('.test.ts'),
        )
        .map((entry) =>
            toPosixPath(relative(repoRoot, join(entry.parentPath, entry.name))),
        )
        .sort((left, right) => left.localeCompare(right));
};

const matchesSlice = (relativePath: string, slice: SliceName): boolean => {
    const isHeavy =
        heavyTestFiles.has(relativePath) ||
        relativePath.startsWith('tests/node/integration/');

    return slice === 'heavy' ? isHeavy : !isHeavy;
};

const runVitest = (files: readonly string[]): void => {
    const result = spawnSync(
        process.execPath,
        [
            packageManagerEntrypoint,
            'exec',
            'vitest',
            '--project',
            'node',
            '--run',
            ...files,
        ],
        {
            cwd: repoRoot,
            stdio: 'inherit',
            env: process.env,
        },
    );

    if (result.status !== 0) {
        throw new Error('Vitest failed for the requested node test slice');
    }
};

const main = async (): Promise<void> => {
    const requestedSlice = process.argv[2];
    if (requestedSlice !== 'fast' && requestedSlice !== 'heavy') {
        throw new Error(
            `Expected a node test slice of "fast" or "heavy", received: ${requestedSlice ?? 'undefined'}`,
        );
    }

    const files = (await collectTestFiles(testsRootUrl)).filter(
        (relativePath) => matchesSlice(relativePath, requestedSlice),
    );

    if (files.length === 0) {
        throw new Error(
            `No node test files matched the "${requestedSlice}" slice`,
        );
    }

    console.log(
        `Running ${requestedSlice} node tests across ${files.length} files.`,
    );
    runVitest(files);
};

void main();
