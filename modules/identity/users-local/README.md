# users-local

## Responsibilities
- Holds a small deployment's users in the provider: each subject and the identifier it was made for, and a password's hash where one is held, on the store, as a user ledger contributed to `users`.
- Makes a new subject for an identifier no user holds, and keeps an identifier for a subject brought from another IdP.

## Not here
- Which answer `users` gives, links, verified contacts, the waits of a password check and refusing a ledger beside `registered` users: `users`.
- A user's attributes: it holds none. Checking a password against a hash: `secret-hash`. Whether a create is allowed: its caller's.
- An outside ledger: `users-http`.

## Offers
- Composition definition only: a contribution to `users`' `ledgers` (verification, by subject, by identifier, a create and `keep`, an import), its spaces and its eraser `users-local` (to `erasure-extensions`' `erasers`).
- It is not the users axis's default, `users-http` is: a composition keeping its users in the provider names it to compose it.
- Operator section `password-work` (optional): a bcrypt or scrypt hash, of any secret, of the work the held passwords' hashes take; every password check does that work.
- Probe `users-local.phase`: out of traffic while the records' phase cannot be read.

## Invariants
- An identifier holds one subject at most, also when two ask at once: a subject and its identifier are written as one, or neither (internal module `records`).
- A subject is 16 bytes drawn from the kernel's random, in lowercase hex, so it tells nothing of its identifier; a create answers `exists` for an identifier held and never writes then.
- `keep` answers `kept` where the identifier is held for the subject, written now or by an earlier import, and `conflict` where the identifier or the subject is held otherwise, writing nothing then.
- A user holds no attributes, and no password unless a hash is held for it.
- A check where no hash is held does the work of `password-work`, as `secret-hash`'s checker does; a held hash of other work takes its own work besides, so set `password-work` to the work of the hashes held. Without it, a check where none is held does no hashing.
- A record of another shape, and a held hash `secret-hash` cannot read, is unavailable, never none.
- Erasing a subject removes its two records; its identifier is then free for a new subject.
- With `users`, it is the one ledger: `users` refuses boot beside another ledger or `registered` users.
- It holds nothing in process, so it is safe on many instances.

## Data
- Two spaces, each kept without end and erased by `users-local` (internal module `records`).

## Depends on
- `kernel`, `users`, `store`, `subject-records`, `secret-hash`, `erasure-extensions`

## Vocabulary
- identifier: what a user is known by to the ledger, matched exactly, as `users` hands it over.
