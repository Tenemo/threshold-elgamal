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
        entryPoint: `scripts/typedoc/entrypoints/${moduleName}.ts`,
        apiIndexPage: `docs/api/${moduleName}/index.md`,
    };
};

export const publicApiDocs = exportKeys.map(toPublicApiDocEntry);

export const typedocEntryPoints = publicApiDocs.map(
    (entry): string => entry.entryPoint,
);
