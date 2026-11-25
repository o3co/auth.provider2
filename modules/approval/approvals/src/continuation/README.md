# continuation

Internal module of `approvals`: the screen's continuations, each taken once in order.

## Responsibilities
- Verifies a continuation's signature by the screen's `eSig` over `sdk-core-wire`'s continuation input, takes its sequence number in one write, runs its step and keeps the step's answer with it.

## Not here
- What a continuation's body asks: the ceremony's owner.

## Offers
- `continuationsOver` (the ring's verifying, the store, the clock) → `continue` and `continuationOf`. `continue`: the run of one continuation, its step handed the creation as its record keeps it (`KeptCreation`: its items as signed, the screen's keys).
  - `continue` (hash, sequence number, body, the screen's signature, its step, handed the creation as kept) → continued with what the step answered (`again` where another call took it first); or refused, `pending` while another call holds its step.
- `continuationOf` (hash) → a creation's last continuation as taken: its sequence number, body as received, signature and, once kept, what its step answered, in one read; none before one is taken, past the statement's expiry, or where this generation's ring does not verify it.

## Invariants
- Only a creation's statement is continued. The signature is ES256 over the input's UTF-8 bytes, `r‖s` in base64url, in its one spelling (its last character's unused bits zero); another spelling is refused `signature`, and a body past 8192 UTF-8 bytes `body`, before anything is read of the step.
- The body as received and the signature are written in the same write that takes their number, and never again for it: a call taking a lapsed hold of the same number keeps them, so what a key change carries is remade alike.
- A sequence number is the last taken plus one, taken only once the last one's answer is kept. One call takes it and holds its step for 30 seconds, in the same write; the same continuation meanwhile answers `pending`, once kept what was kept, and with any other body `seq`. The signature is checked before anything is written, and expiry before a new number.
- A step runs only under its call's hold, and its answer is kept only while that call holds it. Where the call fell before keeping it, the same continuation runs the step again once the hold lapsed, so a step takes a second run alike.

## Depends on
- `sdk-core-wire` (the continuation's input); the package's `statement` (the record).
