import { typedocEntryPoints } from './typedoc/public-api-docs';

/** @type {import('typedoc').TypeDocOptions} */
const config = {
    entryPoints: typedocEntryPoints,
    entryPointStrategy: 'resolve',
    alwaysCreateEntryPointModule: true,
    plugin: ['typedoc-plugin-markdown', './typedoc/sentence-case-plugin.ts'],
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
