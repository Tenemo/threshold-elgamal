import { readFileSync } from 'node:fs';

type PackageManifest = {
    exports: Record<string, unknown>;
    name: string;
};

export type PublicApiDocEntry = {
    apiIndexPage: string;
    entryPoint: string;
    exportKey: string;
    moduleName: string;
};

export const docsContentRoot = 'docs/src/content/docs';
export const apiDocsRoot = `${docsContentRoot}/api`;
export const apiReferenceRoot = `${apiDocsRoot}/reference`;
export const apiNavigationJson = `${apiReferenceRoot}/navigation.json`;

const manifest = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as PackageManifest;

const exportKeys = Object.keys(manifest.exports).filter(
    (key): boolean => key === '.' || key.startsWith('./'),
);

const toModuleName = (exportKey: string): string =>
    exportKey === '.' ? manifest.name : exportKey.slice(2);

const toPublicApiDocEntry = (exportKey: string): PublicApiDocEntry => {
    const moduleName = toModuleName(exportKey);

    return {
        exportKey,
        moduleName,
        entryPoint: `typedoc/entrypoints/${moduleName}.ts`,
        apiIndexPage: `${apiReferenceRoot}/${moduleName}/index.md`,
    };
};

export const publicApiDocs = exportKeys.map(toPublicApiDocEntry);

export const typedocEntryPoints = publicApiDocs.map(
    (entry): string => entry.entryPoint,
);
