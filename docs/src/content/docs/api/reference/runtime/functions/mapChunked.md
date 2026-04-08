---
title: "mapChunked"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [runtime](../) / mapChunked

# Function: mapChunked()

> **mapChunked**\<`TItem`, `TResult`\>(`items`, `worker`, `options?`): `Promise`\<readonly `TResult`[]\>

Applies an async worker to every item in order while yielding between
chunks.

## Type parameters

### TItem

`TItem`

### TResult

`TResult`

## Parameters

### items

readonly `TItem`[]

Ordered input items.

### worker

(`item`, `index`, `items`) => `Promise`\<`TResult`\>

Async worker applied to each item.

### options?

[`ChunkedRuntimeOptions`](../type-aliases/ChunkedRuntimeOptions/) = `{}`

Chunking and progress options.

## Returns

`Promise`\<readonly `TResult`[]\>

Ordered worker results.
