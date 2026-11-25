# users-local

## Responsibilities
- Holds a small deployment's users in the provider: each subject, the identifier it was made for and the password's hash brought with it, on the store, as a user ledger contributed to `users`.
- Makes a new subject for an identifier no user holds, and keeps an identifier for a subject brought from another IdP.
- Keeps the passkey witness's marks (`passkey-witness`' contract) in its own space, beside the passkeys in the Core's store, and declares where that leaves the promises.

## Not here
- Which answer `users` gives, verified contacts, the waits of a password check and refusing a ledger beside `registered` users: `users`.
- Tying an identifier to an identifierless subject later (§4.3, the app's): the built-in ledger has no way yet (`keep` of a held subject is `conflict`).
- A user's attributes: it holds none. Making a password's hash: the IdP it was brought from. Whether a create is allowed: its caller's.
- An outside ledger: `users-http`. A witness kept apart from the Core's store: `passkey-witness-http`.
- When a mark is set or withdrawn, and what is decided with it: `passkey-witnessing` and `passkeys`.

## Offers
- Composition definition only: a contribution to `users`' `ledgers` (verification, by subject, by identifier, a create, an identifierless create (F1) and `keep`, an import with a password's hash, its `passwords` of `password-work`), a passkey witness (`passkey-witness`' `passkeyWitnesses`), a stance (`promises`' `stances`), its spaces and its eraser `users-local` (to `erasure-extensions`' `erasers`).
- It is not the users axis's default, `users-http` is: a composition keeping its users in the provider names it to compose it.
- Probe `users-local.phase`: out of traffic while the records' phase cannot be read.
- Operator section `users-local`: `password-work`, required, the work every password's hash it holds is of, as `secret-hash` names a work (`scrypt:15,8,1,32,16`).

## Invariants
- An identifier holds one subject at most, also when two ask at once: a subject and its identifier are written as one, or neither (internal module `records`).
- A subject is 16 bytes drawn from the kernel's random, in lowercase hex, so it tells nothing of its identifier; a create answers `exists` for an identifier held and never writes then. An identifierless create answers the subject its key holds, or places one under it with the subject's record naming the key, as one; one placed at once by another is read back, so a key names one subject.
- `keep` answers `kept` where the identifier is held for the subject, written now or by an earlier import, and `conflict` where the identifier or the subject is held otherwise, or the subject is erased, writing nothing then; a create meeting an erased subject is unavailable.
- A password check reads the identifier's record and computes `password-work` once, whether the identifier is held with a hash, with none, or not at all (`secret-hash`'s decoy), so its work tells nothing of who exists; it matches only a held hash.
- A hash is kept only of `password-work` (another is the caller's TypeError), and `keep` answers `kept` again only for the same hash, or none, as held: an identifier kept without a hash takes none later (`conflict`), so a run that brings passwords brings them with the identifiers.
- A hash held of another work, or one it cannot read, makes a check of the identifier unavailable, as its computation would tell it apart. Changing `password-work` makes every hash held unusable so: they are brought again at the new work.
- A record of another shape is unavailable, never none.
- Erasing a subject removes its two records and its mark; its identifier is then free for a new subject. The mark goes with them whatever the keys: the erasure boundary is to be taken in first, as a key standing after it has no mark, and a mark asked for the erased subject is unavailable.
- With `users`, it is the one ledger: `users` refuses boot beside another ledger or `registered` users.
- Its witness keeps `passkey-witness`' promises over the store's: a mark is set unless one is, and removed only as its token's, each in one write. An enroll finding a mark gone before it reads its token sets it again, 3 times at most, then is unavailable. A mark of another shape is unavailable; none is set for an erased subject (unavailable).
- It stands breaking `store-write`: its users and its witness's marks are records in the Core's store, the marks beside the passkeys, so a store emptied or rolled back takes them unseen: a subject's identifier may move, and a subject holding a passkey reads as holding none.
- Composed beside `passkey-witness-http`, two witnesses stand, and `passkey-witnessing` refuses boot: users kept here take their witness here too.
- It holds nothing in process, so it is safe on many instances.

## Data
- Four spaces, each kept without end, `authenticated` among their guarantees (over the memory store, they boot only under `store.accept-unauthenticated`), and erased by `users-local` (internal module `records`): the identifiers, the identifierless subjects' keys, the subjects and the witness's marks.

## Depends on
- `kernel`, `users`, `passkey-witness`, `promises`, `secret-hash`, `store`, `subject-records`, `erasure-extensions`

## Vocabulary
- identifier: what a user is known by to the ledger, matched exactly, as `users` hands it over.
