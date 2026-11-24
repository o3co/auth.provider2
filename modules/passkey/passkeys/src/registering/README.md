# registering

Internal module of `passkeys`: registering and removing keys, over the reservation and the credential records.

## Responsibilities
- Makes, verifies, cancels and replaces a subject's one reservation, holding each change to the frame; decides a registration's and a removal's key change (KE-C01) on the flow; binds and releases credential records.

## Not here
- The reservation's shape, the kind's end, and the pure rules of `commit` and `remove`: the package's records. Reading the keys, the credential records and the counts: the internal module `kept`.

## Offers
- `registeringOver` (the kept parts, `transparency`, the witnessing, `settle`, the clock, tokens, the lapse, the most keys) → the package's `Registrations`.

## Invariants
- The reservation: reserved → verified (`verifyPending`) → active (end `took`); a verified one ends `held` or `abandoned` as ended, and stays verified on any other end. Reserved, verified and ended ones are cancelled, or replaced by a retry (keeping their key generation) or once lapsed. Being put on the log is shown by the frame alone.
- `reserve`, `verifyPending` and `cancel` change it only through `transparency`'s `changeHeld`, held to what they read: never while an op is open on the flow (`open`), never in the store directly. A `first` one is reserved only where the settled keys and the witness's mark both say none.
- `commit` decides only on a verified reservation, by its verification, before it lapses, under the key generation it was reserved under, while the subject holds fewer than `max-credentials` keys, none for a `first` one. The writer's changes register its key alone: approved by none exactly for a `first` one, removing none. The writer's own records of the kind are written as it gives them.
- `remove` refuses a removal after which the subject holds no key, each key whose chain holds the removed one counted (`authority-rules`' `withoutRooted`), and the reservation's op.
- `verifyPending` answers the response and challenge that verified a reservation alike again, saving its count first; any other is checked anew. A count is never lowered.
- A binding carries the version of the reservation that made it. A release (a cancel, a replacement, a reserve that bound and then lost) unbinds only while the binding carries its version, and never a credential active now or found active by a settle. `reserve` refuses another subject's binding, or other details, and never rewrites the details kept.

## Depends on
- `webauthn` (the credential's form), `transparency`; the package's contract and records, and the internal module `kept`.
