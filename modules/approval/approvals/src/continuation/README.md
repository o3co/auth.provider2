# continuation

Internal module of `approvals`: the screen's continuations, each taken once in order.

## Responsibilities
- Verifies a continuation's signature by the screen's `eSig` over its stage's input (a creation's `register`, `sdk-core-wire`'s; a T's `sign-up` and a passkey-manage's sealed `delete` and `rename`, `continuation-wire`'s, a sealed one opened here first), takes its sequence number in one write, runs its step and keeps the step's answer with it.

## Not here
- What a continuation's body asks: the ceremony's owner.

## Offers
- `continuationsOver` (the ring's verifying and opening, the store, the clock) → `continue`, `continueSignUp`, `continueSealed` and `continuationOf`. `continue`: the run of one continuation, its step handed the creation as its record keeps it (`KeptCreation`: its items as signed, the screen's keys).
  - `continue` (hash, sequence number, body, the screen's signature, its step, handed the creation as kept) → continued with what the step answered (`again` where another call took it first); or refused, `pending` while another call holds its step.
- `continueSignUp` (T's hash, 1, the body `{}`, the screen's signature, its step, handed the T as kept: `KeptSignUp`, its hash, bytes, items and the screen's keys) → as `continue`, the step's `SignUpResult` (`{ creation }` or `{ refused }`); or refused, also `purpose` (no T, or one whose owner did not allow it), `used` (T no longer issued), `expired`.
- `continueSealed` (a passkey-manage's hash, stage, number 1 to 16, the sealing, its step, handed `KeptManage`: the hash, subject, approving key's credential and registration, the screen's keys, and `until`, when its record is gone (60 seconds past the statement's expiry), past which none of its steps runs; and `OpenedBody`: the stage, the body read, its hash) → as `continue`; or refused, also `sealed`.
- `continuationOf` (hash) → a creation's last continuation as taken: its sequence number, body as received, signature and, once kept, what its step answered, in one read; none before one is taken, past the statement's expiry, or where this generation's ring does not verify it.

## Invariants
- A creation's statement is continued by `register`, a T by `sign-up` alone (F1): only a T its owner allowed it at its issue (`continues`), number 1, the body `{}`.
  - Its write checks the T still issued and unexpired, on either path that takes it, and marks its sign-up begun (`signUp`), keeping one begun: a T used first is never begun, one begun is used only as `statement` says.
  - A kept answer is given again past expiry; a step runs again only within T's life. The signature is ES256 over the input's UTF-8 bytes, `r‖s` in base64url, in its one spelling (its last character's unused bits zero); another spelling is refused `signature`, and a body past 8192 UTF-8 bytes `body`, before anything is read of the step.
- The body as received and the signature are written in the same write that takes their number, and never again for it: a call taking a lapsed hold of the same number keeps them, so what a key change carries is remade alike.
- A sequence number is the last taken plus one, taken only once the last one's answer is kept. One call takes it and holds its step for 30 seconds, in the same write; the same continuation meanwhile answers `pending`, once kept what was kept, and with any other body `seq`. The signature is checked before anything is written, and expiry in the write that takes a new number.
- A step runs only under its call's hold, and its answer is kept only while that call holds it. Where the call fell before keeping it, the same continuation runs the step again once the hold lapsed, so a step takes a second run alike. A number taken is taken again only before its record's end, 60 seconds past the statement's expiry: no step runs past it.
- A sealed continuation goes on only from a passkey-manage used, while this generation's ring verifies it: its sealing exactly `plainBytes` and the tag long, opened under its stage, statement hash and number, read by its stage's shape, its signature checked, before anything is written; each failure is `sealed` alike. A holder that withdrew the opening throws. Its body's hash alone is kept, never the opened text.

## Depends on
- `sdk-core-wire` (the register input, HPKE's info), `continuation-wire` (the sign-up and sealed stages' inputs, bodies and plaintext), `keys` (opening); the package's `statement` (the record). The register input moves to `continuation-wire` once its users have (the same bytes; `sdk-core-wire`'s is then taken out).
