---
title: "ChunkedRuntimeOptions"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [runtime](../) / ChunkedRuntimeOptions

# Type alias: ChunkedRuntimeOptions

> **ChunkedRuntimeOptions** = `object`

Options shared by chunked runtime helpers.

## Properties

### chunkSize?

> `readonly` `optional` **chunkSize?**: `number`

Maximum items processed before yielding back to the event loop.

***

### onProgress?

> `readonly` `optional` **onProgress?**: (`progress`) => `void`

Optional progress callback invoked after each processed chunk.

#### Parameters

##### progress

[`RuntimeProgress`](RuntimeProgress/)

#### Returns

`void`
