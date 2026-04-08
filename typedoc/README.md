# Typedoc tooling

This directory contains the source used to generate the API reference under
`docs/src/content/docs/api/reference/`.

## Output model

`docs/src/content/docs/api/reference/` is generated output. It is built locally
by `pnpm run docs:api`, verified by `pnpm run verify:docs`, ignored in Git, and
regenerated in CI and the Pages deployment workflow.
