# users-local

## Responsibilities
- Holds a small deployment's users in the provider: each subject and the identifier it was made for, on the store, as a user ledger contributed to `users`.
- Makes a new subject for an identifier no user holds, and keeps an identifier for a subject brought from another IdP.
- Keeps the passkey witness's marks (`passkey-witness`' contract) in its own space, beside the passkeys in the Core's store, and declares where that leaves the promises.

## Not here
- Which answer `users` gives, verified contacts, the waits of a password check and refusing a ledger beside `registered` users: `users`.
- A user's attributes and passwords: it holds none. Whether a create is allowed: its caller's.
- An outside ledger: `users-http`. A witness kept apart from the Core's store: `passkey-witness-http`.
- When a mark is set or withdrawn, and what is decided with it: `passkey-witnessing` and `passkeys`.

## Offers
- Composition definition only: a contribution to `users`' `ledgers` (verification, by subject, by identifier, a create and `keep`, an import), a passkey witness (`passkey-witness`' `passkeyWitnesses`), a stance (`promises`' `stances`), its spaces and its eraser `users-local` (to `erasure-extensions`' `erasers`).
- It is not the users axis's default, `users-http` is: a composition keeping its users in the provider names it to compose it.
- Probe `users-local.phase`: out of traffic while the records' phase cannot be read.

## Invariants
- An identifier holds one subject at most, also when two ask at once: a subject and its identifier are written as one, or neither (internal module `records`).
- A subject is 16 bytes drawn from the kernel's random, in lowercase hex, so it tells nothing of its identifier; a create answers `exists` for an identifier held and never writes then.
- `keep` answers `kept` where the identifier is held for the subject, written now or by an earlier import, and `conflict` where the identifier or the subject is held otherwise, or the subject is erased, writing nothing then; a create meeting an erased subject is unavailable.
- A user holds no attributes and no password: a password check answers none for every identifier, reading nothing, so it tells nothing of who exists.
- A record of another shape is unavailable, never none.
- Erasing a subject removes its two records; its identifier is then free for a new subject.
- With `users`, it is the one ledger: `users` refuses boot beside another ledger or `registered` users.
- Its witness keeps `passkey-witness`' promises over the store's: a mark is set unless one is, and removed only as its token's, each in one write. An enroll finding a mark gone before it reads its token sets it again, 3 times at most, then is unavailable. A mark of another shape is unavailable; none is set for an erased subject (unavailable).
- It stands breaking `store-write`: its witness keeps its marks in the Core's store beside the passkeys, so a store emptied or rolled back takes both, and the subject reads as holding no passkey.
- It holds nothing in process, so it is safe on many instances.

## Data
- Three spaces, each kept without end, `authenticated` among their guarantees (over the memory store, they boot only under `store.accept-unauthenticated`), and erased by `users-local` (internal module `records`): the identifiers, the subjects and the witness's marks.

## Depends on
- `kernel`, `users`, `passkey-witness`, `promises`, `store`, `subject-records`, `erasure-extensions`

## Vocabulary
- identifier: what a user is known by to the ledger, matched exactly, as `users` hands it over.
