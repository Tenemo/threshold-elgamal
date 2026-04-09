import { spawnSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const repoRootUrl = new URL('../../', import.meta.url);
const repoRoot = fileURLToPath(repoRootUrl);

const packageManagerEntrypoint = process.env.npm_execpath;
if (packageManagerEntrypoint === undefined) {
    throw new Error('npm_execpath is required to run package manager commands');
}

const vectorFiles = [
    'test-vectors/threshold.json',
    'test-vectors/protocol.json',
] as const;

const runPackageManager = (args: readonly string[]): void => {
    const result = spawnSync(
        process.execPath,
        [packageManagerEntrypoint, ...args],
        {
            cwd: repoRoot,
            stdio: 'inherit',
            env: process.env,
        },
    );

    if (result.status !== 0) {
        throw new Error(`Command failed: pnpm ${args.join(' ')}`);
    }
};

const main = async (): Promise<void> => {
    const beforeEntries = await Promise.all(
        vectorFiles.map(async (relativePath) => {
            const originalContent = await readFile(
                new URL(relativePath, repoRootUrl),
                'utf8',
            );

            return [relativePath, originalContent] as const;
        }),
    );
    const before = new Map<string, string>(beforeEntries);

    try {
        runPackageManager([
            'exec',
            'tsx',
            './tools/generate-threshold-vectors.ts',
        ]);
        runPackageManager([
            'exec',
            'tsx',
            './tools/generate-protocol-vectors.ts',
        ]);

        const changedFiles: string[] = [];
        for (const relativePath of vectorFiles) {
            const current = await readFile(
                new URL(relativePath, repoRootUrl),
                'utf8',
            );
            if (current !== before.get(relativePath)) {
                changedFiles.push(relativePath);
            }
        }

        if (changedFiles.length > 0) {
            throw new Error(
                `Generated vectors drifted from the committed fixtures: ${changedFiles.join(', ')}`,
            );
        }
    } finally {
        await Promise.all(
            vectorFiles.map(async (relativePath) => {
                const original = before.get(relativePath);
                if (typeof original === 'string') {
                    await writeFile(
                        new URL(relativePath, repoRootUrl),
                        original,
                        'utf8',
                    );
                }
            }),
        );
    }

    console.log('Committed test vectors match the generators.');
};

void main();
