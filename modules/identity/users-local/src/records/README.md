# records

Internal module of `users-local`: its two spaces, a user placed in both as one, each read back, and its eraser over them.

## Responsibilities
- Declares the spaces, and places a user by identifier and subject in one write.
- Reads an identifier's or a subject's record in the shape it was written in.
- Erases a subject's records, and migrates both spaces once: the eraser `users-local`.

## Not here
- What a record means to `users`, the subject drawn and the password checked: the package.
- Building the records over the phase: `subject-records`, through the package's module.

## Offers
- `identifierSpace`, `subjectSpace`, and `placed`, the builders' contract, the package's own.
- `localRecords` (the builders) → `place` (identifier, subject, a hash or none) → `placed`, `exists` (the identifier held) or `taken` (else the subject held), `byIdentifier`, `bySubject`.
- `localEraser` (the builders) → the eraser `users-local`.

## Invariants
- `place` writes both records as one change across the two spaces (`subject-records`' joint change), or neither: `exists` where the identifier's record is held, else `taken` where the subject's is; a subject erased is unavailable.
- A record is read as written: an identifier's an object with a non-empty `subject` and, where held, a non-empty `password-hash`; a subject's one with a non-empty `identifier`. Another shape is unavailable.
- Both spaces are `online-indexed`, no eviction, durable, replicated and with confirmed reads, as a joint change needs one set of guarantees; their store writes two partitions as one, else readiness fails with the reason.
- The eraser is `erasable`; its `window` erases each subject as `online` does, both spaces indexed by their subject. The migration reads an identifier's record by the subject it holds, and a subject's by its key.

## Data
- Format 1: `users-local.identifiers`, keyed by the identifier: `{ subject, password-hash? }`. `users-local.subjects`, keyed by the subject: `{ identifier }`. Each with its index space.

## Depends on
- `kernel`, `store` (the space declaration), `subject-records` (the builders' types), `erasure-extensions` (the eraser, its reports and readings)
