# continuation

Internal module of `approvals`: the screen's continuations, each taken once in order.

## Responsibilities
- Verifies a continuation's signature by the screen's `eSig` over `sdk-core-wire`'s continuation input, takes its sequence number in one write, runs its step and keeps the step's answer with it.

## Not here
- What a continuation's body asks: the ceremony's owner.

## Offers
- `continuationsOver` (the store, the clock) → the run of one continuation, its step handed the creation as its record keeps it (`KeptCreation`: its items as signed, the screen's keys).

## Invariants
- Only a creation's statement is continued. The signature is ES256 over the input's UTF-8 bytes, `r‖s` in base64url.
- A sequence number is the last taken plus one, taken only once the last one's answer is kept. One call takes it and holds its step for 30 seconds, in the same write; the same continuation meanwhile answers `pending`, once kept what was kept, and with any other body `seq`. The signature is checked before anything is written, and expiry before a new number.
- A step runs only under its call's hold, and its answer is kept only while that call holds it. Where the call fell before keeping it, the same continuation runs the step again once the hold lapsed, so a step takes a second run alike.

## Depends on
- `sdk-core-wire` (the continuation's input); the package's `statement` (the record).
