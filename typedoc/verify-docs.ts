import { promises as fs } from 'node:fs';
import path from 'node:path';

import {
    Application,
    Comment,
    ReflectionKind,
    type DeclarationReflection,
} from 'typedoc';

import typedocConfig from '../typedoc.config.mjs';

import {
    apiNavigationJson,
    docsContentRoot,
    publicApiDocs,
} from './public-api-docs';

const repoRoot = process.cwd();
const docsRoot = path.resolve(repoRoot, docsContentRoot);
const publicRoot = path.resolve(repoRoot, 'docs/public');
const markdownRoots = ['README.md', docsContentRoot];
const documentedPublicApi = publicApiDocs as readonly {
    apiIndexPage: string;
    moduleName: string;
}[];
const requiredApiEntryPages = [
    `${docsContentRoot}/api/index.mdx`,
    `${docsContentRoot}/api/root-package.mdx`,
    `${docsContentRoot}/api/subpath-overview.mdx`,
    ...documentedPublicApi.map((entry) => entry.apiIndexPage),
    apiNavigationJson,
] as const;
const requiredApiModules = new Set(
    documentedPublicApi.map((entry) => entry.moduleName),
);

const markdownLinkPattern = /!?\[[^\]]*]\(([^)]+)\)/g;
const linkTargetPattern = /^([^\s]+)(?:\s+["'][^"']*["'])?$/;

const isExternalLink = (target: string): boolean =>
    target.startsWith('#') ||
    target.startsWith('//') ||
    /^[a-z][a-z0-9+.-]*:/i.test(target);

const normalizeLinkTarget = (rawTarget: string): string => {
    const trimmed = rawTarget.trim().replace(/^<|>$/g, '');
    const match = linkTargetPattern.exec(trimmed);
    return (match?.[1] ?? trimmed).split('#', 1)[0].split('?', 1)[0];
};

const toRepoRelativePath = (absolutePath: string): string =>
    path.relative(repoRoot, absolutePath).replace(/\\/g, '/');

const fileExists = async (candidate: string): Promise<boolean> => {
    try {
        const stats = await fs.stat(candidate);
        return stats.isFile();
    } catch {
        return false;
    }
};

const resolveLinkCandidates = (
    fromFile: string,
    normalizedTarget: string,
): string[] => {
    const fromDocsRoute =
        normalizedTarget === '/' ||
        normalizedTarget.startsWith('/guides/') ||
        normalizedTarget.startsWith('/spec/') ||
        normalizedTarget.startsWith('/api/');
    const absoluteTarget = normalizedTarget.startsWith('/')
        ? normalizedTarget === '/'
            ? docsRoot
            : path.resolve(
                  fromDocsRoute ? docsRoot : repoRoot,
                  normalizedTarget === '/' ? '.' : normalizedTarget.slice(1),
              )
        : path.resolve(path.dirname(fromFile), normalizedTarget);
    const extension = path.extname(absoluteTarget).toLowerCase();
    const candidates = new Set<string>([absoluteTarget]);

    if (normalizedTarget.endsWith('/')) {
        candidates.add(path.join(absoluteTarget, 'index.md'));
        candidates.add(path.join(absoluteTarget, 'index.mdx'));
        candidates.add(path.join(absoluteTarget, 'README.md'));
    }

    if (extension === '') {
        candidates.add(`${absoluteTarget}.md`);
        candidates.add(`${absoluteTarget}.mdx`);
        candidates.add(path.join(absoluteTarget, 'index.md'));
        candidates.add(path.join(absoluteTarget, 'index.mdx'));
        candidates.add(path.join(absoluteTarget, 'README.md'));
    }

    if (extension === '.html') {
        if (normalizedTarget.startsWith('/')) {
            candidates.add(path.resolve(publicRoot, normalizedTarget.slice(1)));
        }
        candidates.add(
            path.join(
                path.dirname(absoluteTarget),
                `${path.basename(absoluteTarget, '.html')}.md`,
            ),
        );
        candidates.add(
            path.join(
                path.dirname(absoluteTarget),
                `${path.basename(absoluteTarget, '.html')}.mdx`,
            ),
        );
    }

    return [...candidates];
};

const collectMarkdownFiles = async (entry: string): Promise<string[]> => {
    const absoluteEntry = path.resolve(repoRoot, entry);
    const stats = await fs.stat(absoluteEntry);

    if (stats.isFile()) {
        return absoluteEntry.endsWith('.md') || absoluteEntry.endsWith('.mdx')
            ? [absoluteEntry]
            : [];
    }

    const files: string[] = [];
    const pending = [absoluteEntry];

    while (pending.length > 0) {
        const current = pending.pop();
        if (current === undefined) {
            continue;
        }

        const entries = await fs.readdir(current, { withFileTypes: true });
        for (const child of entries) {
            const childPath = path.join(current, child.name);
            if (child.isDirectory()) {
                pending.push(childPath);
            } else if (
                child.isFile() &&
                (childPath.endsWith('.md') || childPath.endsWith('.mdx'))
            ) {
                files.push(childPath);
            }
        }
    }

    return files.sort();
};

const verifyLinks = async (): Promise<string[]> => {
    const markdownFiles = (
        await Promise.all(
            markdownRoots.map((entry) => collectMarkdownFiles(entry)),
        )
    ).flat();
    const failures: string[] = [];

    for (const file of markdownFiles) {
        const content = await fs.readFile(file, 'utf8');
        for (const match of content.matchAll(markdownLinkPattern)) {
            const normalizedTarget = normalizeLinkTarget(match[1]);
            if (normalizedTarget === '' || isExternalLink(normalizedTarget)) {
                continue;
            }

            const candidates = resolveLinkCandidates(file, normalizedTarget);
            let resolved = false;
            for (const candidate of candidates) {
                if (await fileExists(candidate)) {
                    resolved = true;
                    break;
                }
            }

            if (!resolved) {
                failures.push(
                    `${toRepoRelativePath(file)} -> ${normalizedTarget}`,
                );
            }
        }
    }

    return failures;
};

const verifyApiEntryPages = async (): Promise<string[]> => {
    const failures: string[] = [];

    for (const relativePath of requiredApiEntryPages) {
        const absolutePath = path.resolve(repoRoot, relativePath);
        if (!(await fileExists(absolutePath))) {
            failures.push(relativePath);
        }
    }

    const navigationPath = path.resolve(repoRoot, apiNavigationJson);
    if (!(await fileExists(navigationPath))) {
        return failures;
    }

    const navigationJson = JSON.parse(
        await fs.readFile(navigationPath, 'utf8'),
    ) as {
        children?: unknown;
        title?: string;
        path?: string;
    }[];
    const seenModules = new Set<string>();

    const visitNavigationItems = (
        items: readonly {
            children?: unknown;
            title?: string;
            path?: string;
        }[],
    ): void => {
        for (const item of items) {
            if (
                typeof item.path === 'string' &&
                item.path.endsWith('/index.md')
            ) {
                seenModules.add(item.path.slice(0, -'/index.md'.length));
            }

            if (Array.isArray(item.children)) {
                visitNavigationItems(
                    item.children as {
                        children?: unknown;
                        title?: string;
                        path?: string;
                    }[],
                );
            }
        }
    };

    visitNavigationItems(navigationJson);

    for (const moduleName of requiredApiModules) {
        if (!seenModules.has(moduleName)) {
            failures.push(`navigation.json missing module "${moduleName}"`);
        }
    }

    for (const moduleName of seenModules) {
        if (moduleName !== undefined && !requiredApiModules.has(moduleName)) {
            failures.push(
                `navigation.json contains non-exported module "${moduleName}"`,
            );
        }
    }

    return failures;
};

const getReflectionSummary = (reflection: DeclarationReflection): string => {
    const comment =
        reflection.comment ??
        reflection.signatures?.find(
            (signature) => signature.comment !== undefined,
        )?.comment;

    return Comment.combineDisplayParts(comment?.summary).trim();
};

const publicReflectionKinds =
    ReflectionKind.Module |
    ReflectionKind.Class |
    ReflectionKind.Function |
    ReflectionKind.TypeAlias |
    ReflectionKind.Interface |
    ReflectionKind.Variable;

const verifyTypedocSummaries = async (): Promise<string[]> => {
    const app = await Application.bootstrapWithPlugins(typedocConfig);
    const project = await app.convert();

    if (project === undefined) {
        throw new Error('TypeDoc could not build the public reflection graph');
    }

    const failures: string[] = [];
    const seen = new Set<string>();

    for (const reflection of project.getReflectionsByKind(
        publicReflectionKinds,
    )) {
        const publicReflection = reflection.isReference()
            ? reflection.getTargetReflectionDeep()
            : reflection;

        if (
            !publicReflection.kindOf(publicReflectionKinds) ||
            publicReflection.isProject()
        ) {
            continue;
        }

        const key = `${publicReflection.kind}:${publicReflection.getFullName()}`;
        if (seen.has(key)) {
            continue;
        }
        seen.add(key);

        const summary = getReflectionSummary(
            publicReflection as DeclarationReflection,
        );
        if (summary === '') {
            failures.push(publicReflection.getFullName());
        }
    }

    return failures.sort();
};

const main = async (): Promise<void> => {
    const linkFailures = await verifyLinks();
    const apiFailures = await verifyApiEntryPages();
    const summaryFailures = await verifyTypedocSummaries();

    const failures: string[] = [];

    if (linkFailures.length > 0) {
        failures.push('Broken relative links:');
        failures.push(...linkFailures.map((failure) => `- ${failure}`));
    }

    if (apiFailures.length > 0) {
        failures.push('Missing generated API entry pages:');
        failures.push(...apiFailures.map((failure) => `- ${failure}`));
    }

    if (summaryFailures.length > 0) {
        failures.push('Public API reflections without a summary:');
        failures.push(...summaryFailures.map((failure) => `- ${failure}`));
    }

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Documentation verification passed.');
};

void main();
