# Typedoc tooling

This directory contains the source used to generate the committed API reference
under `docs/api/`.

## Why `docs/api/` stays tracked

For this repository, keeping the generated API reference committed is useful:

- `docs/` is the published documentation tree
- the repository needs a browsable API snapshot alongside the source
- link verification runs against the committed markdown output, not only against
  a local temporary build

In the current repository layout, keeping `docs/api/` tracked is intentional.
