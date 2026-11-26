# registering

Internal module of `passkeys`: registering and removing keys, over the reservation and the credential records.

## Responsibilities
- Makes, verifies, cancels and replaces a subject's one reservation, holding each change to the frame; runs a registration's and a removal's key change (KE-C01) on the flow through `transparency`'s `decide`; binds and releases credential records.

## Not here
- The reservation's shape, the kind's end, and the pure rules of `commit` and `remove`: the internal module `records`. Reading the keys, the credential records and the counts: the internal module `kept`.

## Offers
- `registeringOver` (the kept parts, `transparency`, the witnessing, `settle`, the clock, tokens, the lapse, the most keys) → the package's `Registrations`.

## Invariants
- The reservation: reserved → verified (`verifyPending`) → active or ended, as `records`' kind ends it. Reserved, verified and ended ones are cancelled, or replaced by a retry (keeping their key generation) or once lapsed. Being put on the log is shown by the frame alone.
- `reserve`, `verifyPending` and `cancel` change it only through `transparency`'s `changeHeld`, held to what they read: never while an op is open on the flow (`open`), never in the store directly. A `first` one is reserved only where the settled keys and the witness's mark both say none.
- `commit` and `remove` decide their key change by `records`' `committing` and `removing` (with `max-credentials` as the most keys), through the writer, on the flow's state as the frame decides it; `commit` judges a reservation's lapse by the time it read when called.
- `verifyPending` answers the response and challenge that verified a reservation alike again, saving its count first; any other is checked anew. A count is never lowered.
- A binding carries the version of the reservation that made it, and its lapse; another reservation of the subject's takes it over only where it replaces that one, or once it lapsed, and a reservation not written hands it back as it found it.
- A release (a cancel, a replacement, a lost reserve that made the binding) unbinds only while the binding carries its version, and never a credential active now or found active by a settle. `reserve` refuses another subject's binding, or other details, and never rewrites the details kept; details it makes, or kept with no time, take its time (kernel clock): when the credential was first reserved to the subject.

## Depends on
- `webauthn` (the credential's form), `transparency`; the package's contract, and the internal modules `records` and `kept`.

## Vocabulary
- version: a reservation's op id; a retry makes a new one.
