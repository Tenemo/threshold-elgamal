---
title: "deriveFinalShare"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [dkg](../) / deriveFinalShare

# Function: deriveFinalShare()

> **deriveFinalShare**(`contributions`, `qual`, `participantIndex`, `q`): `object`

Derives one participant's final share by summing accepted share
contributions from qualified dealers.

## Parameters

### contributions

readonly [`AcceptedShareContribution`](../type-aliases/AcceptedShareContribution/)[]

Local accepted share contributions.

### qual

readonly `number`[]

Qualified dealer indices.

### participantIndex

`number`

Recipient participant index.

### q

`bigint`

Prime-order subgroup order.

## Returns

`object`

Final indexed share for the participant.

### index

> `readonly` **index**: `number`

### value

> `readonly` **value**: `bigint`
