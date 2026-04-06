/** @type {import('typedoc').TypeDocOptions} */
const config = {
    entryPoints: [
        'scripts/typedoc/entrypoints/threshold-elgamal.ts',
        'scripts/typedoc/entrypoints/core.ts',
        'scripts/typedoc/entrypoints/elgamal.ts',
        'scripts/typedoc/entrypoints/serialize.ts',
    ],
    entryPointStrategy: 'resolve',
    alwaysCreateEntryPointModule: true,
    plugin: [
        'typedoc-plugin-markdown',
        './scripts/typedoc-sentence-case-plugin.ts',
    ],
    out: 'docs/api',
    router: 'member',
    readme: 'typedoc.readme.md',
    entryFileName: 'index.md',
    navigationJson: 'docs/api/navigation.json',
    cleanOutputDir: true,
    githubPages: false,
    hideGenerator: true,
    disableSources: true,
    excludeExternals: true,
    excludePrivate: true,
    excludeProtected: true,
    excludeInternal: true,
    classPropertiesFormat: 'table',
    interfacePropertiesFormat: 'table',
    indexFormat: 'table',
};

export default config;
