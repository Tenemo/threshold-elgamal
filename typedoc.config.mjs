/** @type {import('typedoc').TypeDocOptions} */
const config = {
    entryPoints: ['src/index.ts'],
    entryPointStrategy: 'resolve',
    alwaysCreateEntryPointModule: true,
    plugin: ['typedoc-plugin-markdown'],
    out: 'docs/src/content/docs/api/reference',
    router: 'member',
    readme: 'typedoc/generated-reference-intro.md',
    entryFileName: 'index.md',
    navigationJson: 'docs/src/content/docs/api/reference/navigation.json',
    cleanOutputDir: true,
    githubPages: false,
    hideGenerator: true,
    disableSources: true,
    excludeExternals: true,
    excludePrivate: true,
    excludeProtected: true,
    excludeInternal: true,
    validation: {
        notExported: false,
    },
    classPropertiesFormat: 'table',
    interfacePropertiesFormat: 'table',
    indexFormat: 'table',
};

export default config;
