# Documentation

This site is split into guides, spec pages, and generated API reference. Start with the guides unless you already know the library and only need exact signatures.

## Guides

- [Guide index](guides/index.html)
- [Getting started](guides/getting-started.html)
- [Additive ElGamal](guides/additive-elgamal.html)
- [Groups and validation](guides/groups-and-validation.html)
- [Runtime and compatibility](guides/runtime-and-compatibility.html)
- [Errors and failure modes](guides/errors-and-failure-modes.html)
- [Security and non-goals](guides/security-and-non-goals.html)

## Spec

- [Spec index](spec/index.html)
- [Library invariants](spec/library-invariants.html)
- [Current suite](spec/library-suite.html)
- [API contract](spec/api-contract.html)
- [Roadmap](spec/roadmap.html)

## API reference

- [API landing page](api/index.html)
- [Safe root package](api/threshold-elgamal/index.html)
- [Core subpath](api/core/index.html)
- [Threshold subpath](api/threshold/index.html)
- [VSS subpath](api/vss/index.html)
- [Proofs subpath](api/proofs/index.html)
- [Protocol subpath](api/protocol/index.html)
- [Transport subpath](api/transport/index.html)
- [DKG subpath](api/dkg/index.html)
- [ElGamal subpath](api/elgamal/index.html)
- [Serialize subpath](api/serialize/index.html)

## Current surface

- `threshold-elgamal` is the safe root package
- `core`, `threshold`, `vss`, `proofs`, `protocol`, `transport`, `dkg`, `elgamal`, and `serialize` are available as narrower subpath imports
- The root package stays additive-only even though threshold, proof, transport, and DKG primitives now ship under subpaths
