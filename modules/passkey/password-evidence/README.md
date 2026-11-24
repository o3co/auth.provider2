# password-evidence

## Responsibilities
- Checks a password as one kind of a first key's evidence (`password`), through `users`, and declares the kind to `promises`.

## Not here
- The password's hash, its check, its work and its waits: `users` and its ledger.
- When a start passes, and its nonce: `passkey-management`'s path.
- Bringing hashes in from another IdP: `users`' `usersImport`.

## Offers
- Contributes `firstKeyEvidence` `password`: its item `password`, the text the screen sent; no `prepare`.
- Contributes `evidenceKinds` `password`, trusting `password`, its strength `guesses` as `users`' `failedChecks` states them: per identifier, so a ledger answering one person under several identifiers gives that many times the guesses.

## Invariants
- `check` asks `users`' `verifyAsPart` for the start's identifier and passes only where the user found is the subject the path names; a subject of none, another subject, no user and any item of another shape fail, after the same check. It never answers `absent`: composed, it is asked of everyone, and one holding no password makes no first key.
- `settled` settles the start's check once, passed only where the start and this kind both passed; one never settled, or told in another process, stays a failure in the identifier's waits.
- At most 10 000 checks await their start's end (a fixed guard); the oldest past it is let go, counted failed.
- A fault of `users` is thrown on, and nothing is held for the start.

## Depends on
- `kernel`, `users`, `passkey-management`, `promises`

## Vocabulary
- start's end: how the path ended a start over every kind, which the password's waits count.
