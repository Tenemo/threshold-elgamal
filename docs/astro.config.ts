import mdx from '@astrojs/mdx';
import StarlightIntegration from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

const normalizeBase = (value: string | undefined): string => {
    const trimmed = (value ?? '/').trim();

    if (!trimmed || trimmed === '/') {
        return '/';
    }

    return `/${trimmed.replace(/^\/+|\/+$/g, '')}`;
};

// Serve docs from the repo subpath on GitHub Pages, but keep local runs at root.
const docsBase = normalizeBase(
    process.env.DOCS_BASE_PATH ??
        (process.env.GITHUB_ACTIONS === 'true' ? '/threshold-elgamal' : '/'),
);

export default defineConfig({
    site: 'https://tenemo.github.io',
    base: docsBase,
    integrations: [
        StarlightIntegration({
            title: 'threshold-elgamal',
            description:
                'Browser-native documentation for threshold-elgamal, a verifiable voting research library built on ElGamal.',
            disable404Route: true,
            social: [
                {
                    icon: 'github',
                    label: 'GitHub',
                    href: 'https://github.com/Tenemo/threshold-elgamal',
                },
            ],
            customCss: ['./src/styles/custom.css'],
            sidebar: [
                {
                    label: 'Guides',
                    items: [
                        'guides/getting-started',
                        'guides/verifying-a-public-board',
                        'guides/browser-and-worker-usage',
                        'guides/published-payload-examples',
                        'guides/three-participant-voting-flow',
                        'guides/runtime-and-compatibility',
                        'guides/security-and-non-goals',
                        'guides/production-voting-safety-review',
                    ],
                },
                {
                    label: 'Protocol spec',
                    items: [
                        'spec',
                        'spec/library-invariants',
                        'spec/api-contract',
                    ],
                },
                {
                    label: 'API reference',
                    items: [
                        'api',
                        'api/root-package',
                        {
                            label: 'Generated reference',
                            collapsed: true,
                            autogenerate: {
                                directory: 'api/reference',
                            },
                        },
                    ],
                },
            ],
        }),
        mdx(),
    ],
});
