---
title: "forEachChunked"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [runtime](../) / forEachChunked

# Function: forEachChunked()

> **forEachChunked**\<`TItem`\>(`items`, `worker`, `options?`): `Promise`\<`void`\>

Executes an async side-effect worker for every item in order while yielding
between chunks.

## Type parameters

### TItem

`TItem`

## Parameters

### items

readonly `TItem`[]

Ordered input items.

### worker

(`item`, `index`, `items`) => `Promise`\<`void`\>

Async worker applied to each item.

### options?

[`ChunkedRuntimeOptions`](../type-aliases/ChunkedRuntimeOptions/) = `{}`

Chunking and progress options.

## Returns

`Promise`\<`void`\>
