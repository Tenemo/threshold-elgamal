export const docsContentRoot = 'docs/src/content/docs';
export const apiReferenceRoot = `${docsContentRoot}/api/reference`;
export const apiNavigationJson = `${apiReferenceRoot}/navigation.json`;

export const publicApiDocs: readonly {
    apiIndexPage: string;
    moduleName: string;
}[] = [
    {
        apiIndexPage: `${apiReferenceRoot}/threshold-elgamal/index.md`,
        moduleName: 'threshold-elgamal',
    },
] as const;
