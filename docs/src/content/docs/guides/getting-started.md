---
title: Get started
description: The shortest safe path into the shipped root package and honest-majority voting flow.
sidebar:
  order: 1
---

Use the root package. The shipped public surface is centered on one protocol story: honest-majority GJKR, fixed `1..10` score ballots, `ballot-close`, and full ceremony verification.

## Start with these rules

- The public manifest shape is only `rosterHash` and `optionList`.
- The library derives the threshold from the accepted registration roster as `k = ceil(n / 2)`.
- Ballots are fixed to complete `1..10` score ballots.
- The organizer closes counting with one signed `ballot-close` payload.
- Tally verification must be done against the close-selected ballot set, not against a server-supplied aggregate.

## Where to go next

- For installation and the top-level package overview, read [README.md](https://github.com/Tenemo/threshold-elgamal#readme).
- For the supported ceremony path, read [Three-participant voting flow](./three-participant-voting-flow/).
- For runtime prerequisites and platform assumptions, read [Runtime and compatibility](./runtime-and-compatibility/).
- For the security boundary, read [Security and non-goals](./security-and-non-goals/).
- For exact signatures and exported types, use the [API docs](../api/).
