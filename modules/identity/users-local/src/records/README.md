# records

Internal module of `users-local`: its four spaces, a user placed in two as one (by identifier, or by an identifierless subject's key), each read back, the witness's marks, and its eraser over them.

## Responsibilities
- Declares the spaces, and places a user by identifier and subject, or an identifierless one by its key and subject, in one write.
- Sets, reads and removes a subject's mark by its token.
- Reads an identifier's, an identifierless subject's key's or a subject's record in the shape it was written in.
- Erases a subject's records and mark, and migrates each space once: the eraser `users-local`.

## Not here
- What a record means to `users`, the subject drawn, the password checked and what a mark answers: the package.
- Building the records over the phase: `subject-records`, through the package's module.

## Offers
- `identifierSpace`, `identifierlessSpace`, `subjectSpace`, `markSpace`, and `placed`, the builders' contract, the package's own.
- `localRecords` (the builders) → `place` (identifier, subject, a password's hash where given) → `placed`, `exists` (the identifier held), `taken` (else the subject held) or `erased` (else the subject erased); `placeIdentifierless` (key, subject) → the same words, `exists` the key held; `byIdentifier`, `byIdentifierlessKey`, `bySubject`.
- `localMarks` (the builders) → `set` (subject, token) → `created`, `exists` or `erased`; `read`; `remove` (subject, token).
- `localEraser` (the builders) → the eraser `users-local`.

## Invariants
- `place` and `placeIdentifierless` each write both records as one change across two spaces (`subject-records`' joint change), or neither: `exists` where the identifier's record is held, else `taken` where the subject's is, else `erased` where the subject's tombstone stands.
- A record is read as written: an identifier's an object with a non-empty `subject`, and a non-empty `passwordHash` where one was brought; an identifierless subject's key's one with a non-empty `subject`; a subject's one with a non-empty `identifier`, or `identifierlessKey` for an identifierless subject. Another shape is unavailable.
- The three user spaces are `online-indexed`, no eviction, durable, replicated, authenticated and with confirmed reads, as a joint change needs one set of guarantees; their store writes two partitions as one, else readiness fails with the reason. The marks' space is `online-keyed`, its key the subject, with the same guarantees.
- A mark is set only where none is and the subject is not erased, and removed only where it holds the token, checked in the write that removes it. A mark is an object with a non-empty `token`; another shape is unavailable.
- The eraser is `erasable`; its `window` erases each subject as `online` does, each space indexed or keyed by its subject. The migration reads an identifier's and an identifierless subject's key's record by the subject it holds, and a subject's and a mark's by its key.

## Data
- Format 1: `users-local.identifiers`, keyed by the identifier: `{ subject, passwordHash? }`. `users-local.identifierless`, keyed by the identifierless subject's key: `{ subject }`. `users-local.subjects`, keyed by the subject: `{ identifier }` or `{ identifierlessKey }`. `users-local.marks`, keyed by the subject: `{ token }`. Each with its index space.

## Depends on
- `kernel`, `store` (the space declaration), `subject-records` (the builders' types), `erasure-extensions` (the eraser, its reports and readings)
