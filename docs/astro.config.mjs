import mdx from '@astrojs/mdx';
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

export default defineConfig({
    site: 'https://tenemo.github.io',
    base: '/threshold-elgamal',
    integrations: [
        starlight({
            title: 'Threshold ElGamal',
            description:
                'Browser-native threshold ElGamal documentation for verifiable voting research prototypes.',
            social: [
                {
                    icon: 'github',
                    label: 'GitHub',
                    href: 'https://github.com/Tenemo/threshold-elgamal',
                },
            ],
            customCss: ['./src/styles/custom.css'],
            editLink: {
                baseUrl:
                    'https://github.com/Tenemo/threshold-elgamal/edit/master/docs/src/content/docs/',
            },
            sidebar: [
                {
                    label: 'Guides',
                    items: [
                        'guides/getting-started',
                        'guides/additive-elgamal',
                        'guides/three-participant-voting-flow',
                        'guides/groups-and-validation',
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
                        'api/subpath-overview',
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
