import { promises as fs } from 'node:fs';
import path from 'node:path';

const repoRoot = process.cwd();
const distRoot = path.resolve(repoRoot, 'dist');
const outputExtensions = new Set(['.js', '.d.ts']);
const specifierPattern =
    /((?:\bimport\s*['"])|(?:\bimport\(\s*['"])|(?:\bfrom\s*['"]))(\.{1,2}\/[^'"()]+)(['"])/g;

const collectOutputFiles = async (directory: string): Promise<string[]> => {
    const files: string[] = [];
    const pending = [directory];

    while (pending.length > 0) {
        const current = pending.pop();
        if (current === undefined) {
            continue;
        }

        const entries = await fs.readdir(current, { withFileTypes: true });
        for (const entry of entries) {
            const entryPath = path.join(current, entry.name);
            if (entry.isDirectory()) {
                pending.push(entryPath);
                continue;
            }

            if (
                entry.isFile() &&
                [...outputExtensions].some((extension) =>
                    entry.name.endsWith(extension),
                )
            ) {
                files.push(entryPath);
            }
        }
    }

    return files.sort();
};

const resolveRuntimeSpecifier = async (
    filePath: string,
    specifier: string,
): Promise<string> => {
    if (path.extname(specifier) !== '') {
        return specifier;
    }

    const absoluteBase = path.resolve(path.dirname(filePath), specifier);
    const fileCandidate = `${absoluteBase}.js`;
    const indexCandidate = path.join(absoluteBase, 'index.js');

    try {
        await fs.stat(fileCandidate);
        return `${specifier}.js`;
    } catch {
        try {
            await fs.stat(indexCandidate);
            return `${specifier}/index.js`;
        } catch {
            throw new Error(
                `Could not resolve emitted runtime target for ${path.relative(
                    repoRoot,
                    filePath,
                )}: ${specifier}`,
            );
        }
    }
};

const rewriteFile = async (filePath: string): Promise<number> => {
    const source = await fs.readFile(filePath, 'utf8');
    let replacements = 0;
    let rewritten = '';
    let lastIndex = 0;

    for (const match of source.matchAll(specifierPattern)) {
        const fullMatch = match[0];
        const prefix = match[1];
        const specifier = match[2];
        const suffix = match[3];
        const matchIndex = match.index;

        if (matchIndex === undefined) {
            continue;
        }

        const runtimeSpecifier = await resolveRuntimeSpecifier(
            filePath,
            specifier,
        );
        rewritten += source.slice(lastIndex, matchIndex);
        rewritten += `${prefix}${runtimeSpecifier}${suffix}`;
        lastIndex = matchIndex + fullMatch.length;

        if (runtimeSpecifier !== specifier) {
            replacements += 1;
        }
    }

    if (replacements === 0) {
        return 0;
    }

    rewritten += source.slice(lastIndex);
    await fs.writeFile(filePath, rewritten);
    return replacements;
};

const main = async (): Promise<void> => {
    const files = await collectOutputFiles(distRoot);
    let totalReplacements = 0;

    for (const file of files) {
        totalReplacements += await rewriteFile(file);
    }

    console.log(
        `Rewrote ${totalReplacements} emitted relative import specifiers in dist.`,
    );
};

void main();
