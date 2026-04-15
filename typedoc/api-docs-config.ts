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
    {
        apiIndexPage: `${apiReferenceRoot}/threshold-elgamal/protocol/index.md`,
        moduleName: 'threshold-elgamal/protocol',
    },
    {
        apiIndexPage: `${apiReferenceRoot}/threshold-elgamal/threshold/index.md`,
        moduleName: 'threshold-elgamal/threshold',
    },
    {
        apiIndexPage: `${apiReferenceRoot}/threshold-elgamal/proofs/index.md`,
        moduleName: 'threshold-elgamal/proofs',
    },
    {
        apiIndexPage: `${apiReferenceRoot}/threshold-elgamal/dkg/index.md`,
        moduleName: 'threshold-elgamal/dkg',
    },
    {
        apiIndexPage: `${apiReferenceRoot}/threshold-elgamal/vss/index.md`,
        moduleName: 'threshold-elgamal/vss',
    },
    {
        apiIndexPage: `${apiReferenceRoot}/threshold-elgamal/elgamal/index.md`,
        moduleName: 'threshold-elgamal/elgamal',
    },
    {
        apiIndexPage: `${apiReferenceRoot}/threshold-elgamal/core/index.md`,
        moduleName: 'threshold-elgamal/core',
    },
] as const;
