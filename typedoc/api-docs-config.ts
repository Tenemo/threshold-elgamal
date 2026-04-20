export const docsContentRoot = 'docs/src/content/docs';
export const apiReferenceRoot = `${docsContentRoot}/api/reference`;
export const apiNavigationJson = `${apiReferenceRoot}/navigation.json`;

export const publicApiDocs: readonly {
    apiPagePath: string;
    moduleName: string;
}[] = [
    {
        apiPagePath: `${apiReferenceRoot}/threshold-elgamal.md`,
        moduleName: 'threshold-elgamal',
    },
    {
        apiPagePath: `${apiReferenceRoot}/threshold-elgamal/protocol.md`,
        moduleName: 'threshold-elgamal/protocol',
    },
    {
        apiPagePath: `${apiReferenceRoot}/threshold-elgamal/threshold.md`,
        moduleName: 'threshold-elgamal/threshold',
    },
    {
        apiPagePath: `${apiReferenceRoot}/threshold-elgamal/proofs.md`,
        moduleName: 'threshold-elgamal/proofs',
    },
    {
        apiPagePath: `${apiReferenceRoot}/threshold-elgamal/dkg.md`,
        moduleName: 'threshold-elgamal/dkg',
    },
    {
        apiPagePath: `${apiReferenceRoot}/threshold-elgamal/vss.md`,
        moduleName: 'threshold-elgamal/vss',
    },
    {
        apiPagePath: `${apiReferenceRoot}/threshold-elgamal/elgamal.md`,
        moduleName: 'threshold-elgamal/elgamal',
    },
    {
        apiPagePath: `${apiReferenceRoot}/threshold-elgamal/core.md`,
        moduleName: 'threshold-elgamal/core',
    },
] as const;
