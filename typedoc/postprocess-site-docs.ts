import { promises as fs } from 'node:fs';
import path from 'node:path';

import {
    apiNavigationJson,
    apiReferenceRoot,
    publicApiDocs,
} from './public-api-docs';

const repoRoot = process.cwd();
const referenceRoot = path.resolve(repoRoot, apiReferenceRoot);
const navigationPath = path.resolve(repoRoot, apiNavigationJson);

type NavigationItem = {
    children?: NavigationItem[];
    path?: string;
    title?: string;
};

const moduleOrder = new Map(
    [
        'threshold-elgamal',
        'core',
        'threshold',
        'vss',
        'proofs',
        'protocol',
        'transport',
        'dkg',
        'elgamal',
        'serialize',
        'runtime',
    ].map((moduleName, index) => [moduleName, index + 1]),
);

const internalLinkPattern = /(!?\[[^\]]*])\(([^)#\s]+)(#[^)]+)?\)/g;
const breadcrumbPattern = /^\*\*.+?\*\*\r?\n\r?\n\*\*\*\r?\n\r?\n/;
const leadingHeadingPattern = /^# .+\r?\n\r?\n/;

const toReferenceRelativePath = (absolutePath: string): string =>
    path.relative(referenceRoot, absolutePath).replace(/\\/g, '/');

const collectMarkdownFiles = async (directory: string): Promise<string[]> => {
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
            } else if (entry.isFile() && entryPath.endsWith('.md')) {
                files.push(entryPath);
            }
        }
    }

    return files.sort();
};

const deriveTitleFromRelativePath = (relativePath: string): string => {
    if (relativePath === 'index.md') {
        return 'Generated reference';
    }

    if (relativePath.endsWith('/index.md')) {
        const segments = relativePath.slice(0, -'/index.md'.length).split('/');
        return segments[segments.length - 1];
    }

    return path.basename(relativePath, '.md');
};

const deriveSidebarOrder = (relativePath: string): number | undefined => {
    if (!relativePath.endsWith('/index.md')) {
        return undefined;
    }

    const moduleName = relativePath.slice(0, -'/index.md'.length);
    return moduleOrder.get(moduleName);
};

const rewriteMarkdownLinks = (content: string): string =>
    content.replace(
        internalLinkPattern,
        (fullMatch, label, rawTarget: string, hash = ''): string => {
            if (
                rawTarget.startsWith('#') ||
                rawTarget.startsWith('http://') ||
                rawTarget.startsWith('https://') ||
                rawTarget.startsWith('mailto:') ||
                !rawTarget.endsWith('.md')
            ) {
                return fullMatch;
            }

            const withoutExtension = rawTarget.slice(0, -'.md'.length);
            const rewrittenTarget = withoutExtension.endsWith('/index')
                ? `${withoutExtension.slice(0, -'/index'.length) || '.'}/`
                : `${withoutExtension}/`;

            return `${label}(${rewrittenTarget}${hash})`;
        },
    );

const main = async (): Promise<void> => {
    const navigation = JSON.parse(
        await fs.readFile(navigationPath, 'utf8'),
    ) as NavigationItem[];
    const titleByPath = new Map<string, string>();

    const visitNavigation = (items: readonly NavigationItem[]): void => {
        for (const item of items) {
            if (
                typeof item.path === 'string' &&
                typeof item.title === 'string'
            ) {
                titleByPath.set(item.path, item.title);
            }

            if (Array.isArray(item.children)) {
                visitNavigation(item.children);
            }
        }
    };

    visitNavigation(navigation);

    const markdownFiles = await collectMarkdownFiles(referenceRoot);
    const publicModules = new Set(
        publicApiDocs.map((entry) => entry.moduleName),
    );

    for (const file of markdownFiles) {
        const relativePath = toReferenceRelativePath(file);
        const title =
            titleByPath.get(relativePath) ??
            deriveTitleFromRelativePath(relativePath);
        const order = deriveSidebarOrder(relativePath);
        const isGeneratedRoot = relativePath === 'index.md';
        const moduleName = relativePath.endsWith('/index.md')
            ? relativePath.slice(0, -'/index.md'.length)
            : undefined;
        const generatedModuleSummary =
            moduleName !== undefined && publicModules.has(moduleName)
                ? `Generated reference page for the \`${moduleName}\` export surface.`
                : undefined;

        let content = await fs.readFile(file, 'utf8');
        content = content.replace(breadcrumbPattern, '');
        content = content.replace(leadingHeadingPattern, '');
        content = rewriteMarkdownLinks(content);

        const frontmatterLines = [
            '---',
            `title: ${JSON.stringify(title)}`,
            isGeneratedRoot
                ? 'description: "Export-driven symbol reference for the current package surface."'
                : generatedModuleSummary !== undefined
                  ? `description: ${JSON.stringify(generatedModuleSummary)}`
                  : null,
            'editUrl: false',
            isGeneratedRoot
                ? 'sidebar:\n  hidden: true'
                : order !== undefined
                  ? `sidebar:\n  order: ${order}`
                  : null,
            '---',
            '',
        ].filter((line): line is string => line !== null);

        await fs.writeFile(file, `${frontmatterLines.join('\n')}${content}`);
    }
};

void main();
