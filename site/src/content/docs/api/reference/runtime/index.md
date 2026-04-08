---
title: "runtime"
description: "Generated reference page for the `runtime` export surface."
editUrl: false
sidebar:
  order: 11
---
[**threshold-elgamal**](../)

***

[threshold-elgamal](../modules/) / runtime

# runtime

Chunked runtime helpers for responsive browser verification work.

This module exposes yielding and chunked iteration primitives for
worker-friendly heavy verification flows.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [ChunkedRuntimeOptions](type-aliases/ChunkedRuntimeOptions/) | Options shared by chunked runtime helpers. |
| [RuntimeProgress](type-aliases/RuntimeProgress/) | Progress callback payload for chunked runtime helpers. |

## Functions

| Function | Description |
| ------ | ------ |
| [forEachChunked](functions/forEachChunked/) | Executes an async side-effect worker for every item in order while yielding between chunks. |
| [mapChunked](functions/mapChunked/) | Applies an async worker to every item in order while yielding between chunks. |
| [yieldToEventLoop](functions/yieldToEventLoop/) | Yields back to the event loop to keep long-running browser work responsive. |
