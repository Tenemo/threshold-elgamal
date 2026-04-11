import path from 'path';
import { fileURLToPath } from 'url';

import { FlatCompat } from '@eslint/eslintrc';
import eslintJs from '@eslint/js';
import { createNodeResolver } from 'eslint-plugin-import-x';
import errorOnlyPlugin from 'eslint-plugin-only-error';
import prettierPluginRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';

const OFF = 0;
const ERROR = 2;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const compat = new FlatCompat({
    baseDirectory: __dirname,
});

export default [
    ...compat.config({
        extends: ['plugin:import-x/errors', 'plugin:import-x/warnings'],
        parser: '@typescript-eslint/parser',
        parserOptions: {
            parser: '@typescript-eslint/parser',
            sourceType: 'module',
            ecmaFeatures: {
                jsx: true,
            },
            project: ['./tsconfig.json', './docs/tsconfig.json'],
            ecmaVersion: 2021,
        },
        plugins: ['only-error'],
        settings: {
            react: {
                version: 'detect',
            },
            'import-x/core-modules': ['threshold-elgamal'],
            'import-x/resolver-next': [
                createNodeResolver({
                    extensions: [
                        '.ts',
                        '.tsx',
                        '.d.ts',
                        '.js',
                        '.jsx',
                        '.json',
                        '.node',
                    ],
                    extensionAlias: {
                        '.js': ['.ts', '.tsx', '.d.ts', '.js'],
                        '.jsx': ['.tsx', '.d.ts', '.jsx'],
                        '.cjs': ['.cts', '.d.cts', '.cjs'],
                        '.mjs': ['.mts', '.d.mts', '.mjs'],
                    },
                    conditionNames: [
                        'types',
                        'import',
                        'esm2020',
                        'es2020',
                        'es2015',
                        'require',
                        'node',
                        'node-addons',
                        'browser',
                        'default',
                    ],
                    mainFields: [
                        'types',
                        'typings',
                        'fesm2020',
                        'fesm2015',
                        'esm2020',
                        'es2020',
                        'module',
                        'jsnext:main',
                        'main',
                    ],
                }),
            ],
        },
    }),
    prettierPluginRecommended,
    {
        files: ['**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx', '**/*.mjs'],
        rules: {
            ...eslintJs.configs.recommended.rules,
            'arrow-parens': [ERROR, 'always', { requireForBlockBody: false }],
            'no-restricted-exports': OFF,
            'no-shadow': OFF, // duplicated by @typescript-eslint/no-shadow

            // @typescript-eslint/eslint-plugin
            '@typescript-eslint/no-use-before-define': ERROR,
            '@typescript-eslint/no-shadow': ERROR,
            '@typescript-eslint/explicit-module-boundary-types': ERROR,
            '@typescript-eslint/unbound-method': ERROR,
            '@typescript-eslint/explicit-function-return-type': [
                ERROR,
                {
                    allowExpressions: true,
                    allowTypedFunctionExpressions: true,
                },
            ],
            '@typescript-eslint/consistent-type-definitions': ['error', 'type'],

            // eslint-plugin-prettier
            'prettier/prettier': [
                ERROR,
                {
                    useTabs: false,
                    semi: true,
                    singleQuote: true,
                    jsxSingleQuote: false,
                    trailingComma: 'all',
                    arrowParens: 'always',
                    endOfLine: 'lf',
                },
            ],

            // eslint-plugin-import-x
            'import-x/no-extraneous-dependencies': [
                ERROR,
                { devDependencies: true },
            ],
            'import-x/prefer-default-export': OFF,
            'import-x/extensions': [
                ERROR,
                'ignorePackages',
                {
                    js: 'never',
                    jsx: 'never',
                    ts: 'never',
                    tsx: 'never',
                },
            ],
            'import-x/order': [
                'error',
                {
                    'newlines-between': 'always',
                    alphabetize: { order: 'asc', caseInsensitive: true },
                    pathGroupsExcludedImportTypes: ['builtin'],
                },
            ],
        },
        plugins: {
            'only-error': errorOnlyPlugin,
        },
        linterOptions: {
            reportUnusedDisableDirectives: true,
        },
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node,
                ...globals.es2021,
                ...globals.commonjs,
            },
        },
    },
    {
        files: ['docs/src/content.config.ts'],
        rules: {
            'import-x/no-unresolved': OFF,
        },
    },
    ...compat.config({
        extends: [
            'plugin:@typescript-eslint/recommended-requiring-type-checking', // adds @typescript-eslint plugin
            'plugin:@typescript-eslint/stylistic-type-checked',
            'plugin:import-x/typescript',
        ],
        overrides: [
            {
                files: ['**/*.mjs', '**/*.js'],
                rules: {
                    '@typescript-eslint/no-unsafe-assignment': OFF,
                    '@typescript-eslint/no-unsafe-member-access': OFF,
                    '@typescript-eslint/no-unsafe-call': OFF,
                },
            },
        ],
    }),
    {
        ignores: [
            'node_modules',
            'node_modules/**',
            'dist',
            'dist/**',
            'coverage',
            'coverage/**',
            'docs/.astro',
            'docs/.astro/**',
            'docs/dist',
            'docs/dist/**',
        ],
    },
];
