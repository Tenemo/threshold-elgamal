import { readdir, readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { exit } from 'node:process';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
);
const v2Directories = ['src/core', 'src/elgamal', 'src/serialize'];
const offenders: string[] = [];

const walk = async (directory: string): Promise<void> => {
    let entries;

    try {
        entries = await readdir(directory, { withFileTypes: true });
    } catch {
        return;
    }

    for (const entry of entries) {
        const entryPath = path.join(directory, entry.name);

        if (entry.isDirectory()) {
            await walk(entryPath);
            continue;
        }

        if (!entry.isFile() || !entry.name.endsWith('.ts')) {
            continue;
        }

        const contents = await readFile(entryPath, 'utf8');
        if (contents.includes('Math.random')) {
            offenders.push(path.relative(rootDir, entryPath));
        }
    }
};

for (const relativeDirectory of v2Directories) {
    await walk(path.join(rootDir, relativeDirectory));
}

if (offenders.length > 0) {
    console.error('Math.random() is forbidden in v2 source directories:');
    for (const offender of offenders) {
        console.error(`- ${offender}`);
    }
    exit(1);
}

console.log('No Math.random() usage found in v2 source directories.');
