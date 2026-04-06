[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / ParticipantIndex

# Type alias: ParticipantIndex

> **ParticipantIndex** = [`Brand`](Brand.md)\<`number`, `"ParticipantIndex"`\>

One-based roster index used by higher-level committee logic.

Roster indices stay as small integers until threshold arithmetic converts
them to bigint values at the `Z_q` boundary.
