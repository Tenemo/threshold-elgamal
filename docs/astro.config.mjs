import mdx from '@astrojs/mdx';
import StarlightIntegration from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

export default defineConfig({
    site: 'https://tenemo.github.io',
    base: '/threshold-elgamal',
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
                        'guides/three-participant-voting-flow',
                        'guides/runtime-and-compatibility',
                        'guides/security-and-non-goals',
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
