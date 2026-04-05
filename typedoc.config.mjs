/** @type {import('typedoc').TypeDocOptions} */
const config = {
    entryPoints: ['src/index.ts'],
    entryPointStrategy: 'resolve',
    plugin: [
        'typedoc-plugin-markdown',
        './scripts/typedoc-sentence-case-plugin.ts',
    ],
    out: 'docs/api',
    router: 'module',
    readme: 'none',
    entryFileName: 'index.md',
    cleanOutputDir: true,
    githubPages: false,
    hideGenerator: true,
    disableSources: true,
    excludeExternals: true,
    excludePrivate: true,
    excludeProtected: true,
    excludeInternal: true,
};

export default config;
