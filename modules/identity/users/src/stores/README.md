# stores

Internal module of `users`: how users writes through its store interface (declared in `store.ts`, the contract), which of its optional ports may be offered together, and users' eraser over it. This module is the mechanics; `store.ts` is the interface.

## Responsibilities
- Writes a subject's contact record, saved with its subject, changed from what it holds.
- Judges, at build, whether the contact store offers its erasure ports as a whole set.
- Erases a subject's contacts, and migrates their space, through those ports: the eraser `users`.
- States what the contact store keeps and needs: verified contacts per subject, kept without end and saved with their subject; no eviction, surviving a crash and a failover.

## Not here
- What the interface is, and what each port answers: `store.ts`. What a contact holds: the package.

## Offers
- `keptFor` (a store, a key, the first record, a change, the subject) → the record before and after: changed where it is there; saved for the subject where it is not.
- `portsRefused` (the contact store) → why its ports cannot be used together, or none: the one statement of the set. `everyPortOffered` (the contact store) → whether the set is offered whole.
- `usersEraser` (the contact store, the reading) → the eraser `users`, contributed to `erasure-extensions`' `erasers`: a subject's contacts erased through the store's `erase`; the one migration through its `migrate`, with the reading the package gives.

## Invariants
- A create that meets a record a read then finds gone is tried again, at most 8 times, then unavailable: a record can now be removed, so `exists` then absent is no proof of another subject's record.
- A save the store answers `erased` (its subject's erasure fences it) is unavailable, never another's answer, and nothing is created; a retry never succeeds, as the fence is for good. users does not check that a subject exists before `verifiedContact`, so a caller holding an erased subject's id meets this on every call; in users' own flows the subject's sessions are revoked, so a request meets it where it was under way as the erasure landed.
- The contact store's `erase` and `migrate` come together, or neither: a part refuses the boot.
- The eraser is `erasable` only where `everyPortOffered`; otherwise it answers empty reports. Its `window` erases each subject as `online` does: contacts are keyed by their subject, so no walk reaches more.

## Depends on
- `kernel` (Unavailable), `erasure-extensions` (the eraser, its reports and readings); users' store interface (`store.ts`).
