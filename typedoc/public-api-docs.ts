type PublicApiDocEntry = {
    apiIndexPage: string;
    entryPoint: string;
    exportKey: string;
    moduleName: string;
};

const rootModuleName = 'threshold-elgamal';

export const docsContentRoot = 'docs/src/content/docs';
const apiDocsRoot = `${docsContentRoot}/api`;
export const apiReferenceRoot = `${apiDocsRoot}/reference`;
export const apiNavigationJson = `${apiReferenceRoot}/navigation.json`;

export const publicApiDocs: readonly PublicApiDocEntry[] = [
    {
        exportKey: '.',
        moduleName: rootModuleName,
        entryPoint: `typedoc/entrypoints/${rootModuleName}.ts`,
        apiIndexPage: `${apiReferenceRoot}/${rootModuleName}/index.md`,
    },
];

export const typedocEntryPoints = publicApiDocs.map(
    (entry): string => entry.entryPoint,
);
