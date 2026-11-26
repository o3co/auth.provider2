# passkeys

## Responsibilities
- Keeps passkeys: a subject's keys, as its flow's state holds them, the one reservation of a key being registered, and each credential's record (its binding to a subject, its count, what its authenticator answered beside the key, a label and a time).
- Owns the reservation's states and the key change's records and end, which its writer registers; answers assertions by active keys through `webauthn`'s ceremonies.

## Not here
- The ceremonies and the relying party: `webauthn`. Challenges, their lifetimes and use-once marks: the caller's, kept with its request.
- The key change's preimage, its `bundle` and `resend`, sending it and taking it in: its writer's and `transparency`'s. The fold: `authority-rules`.
- A reset, emptying a subject's keys: the embedder's signed instruction, put on the log as the boundary record (A11) and taken in through the keys' owner, the fold moving the key generation on (`passkey-reset`).
- Who may register a key, on what grounds, and for which subject: the caller's, standing on the promises. Keeping the witness's mark: the module contributing `passkeyWitnessing`. Auditing a mark beside no key, the sign of a lost store: the key management package.
- Who may rename a key, and the list's completion: the key management package, `approvals`.

## Offers
- `passkeys`, for any module, its asks and answers internal module `kept`'s: `assert`, an assertion by an active key; `publicKeyOf`, an active key's subject, public key and registration; `settle`, the witness's mark and the removals brought in line after a key change. A key is held in one form, its COSE_Key as `webauthn` attests it: the form its ceremonies assert by and the transparency rules judge by.
- `passkeyGenerations`: `generation` (subject) → its key generation in the applied state: the `kg` of L0's reset instruction, behind the log's head until a boundary is taken in (read after a `tend`); L1's embedder reads the monitor's `stateOf` (V22).
- `heldKeys`, read alone: internal module `kept`.
- `keyList`, taken as `registrations` is, internal module `listing`'s: `listOf`, a subject's keys, labels and times; `rename`.
- `registrations`, taken only by a module standing on the promises (`promises`' `stances`): `reserve` (the key generation its approval names; `first`: only where the subject holds no key; `retrying` one), `verifyPending`, `commit` (KE-C01, its op the reservation), `cancel`, `remove` (KE-C01 of a removal).
- `passkeyChanges`: the key change's kind (name, part, records, end) its writer registers on `operationKinds`, with its `bundle` and `resend`, and records of its own after passkeys'. `passkeyPart`: the part, which its wiring binds.
- Extension points `passkeyWitnessing` (at most one: `marked`, `mark` and `withdraw`, by key generation) and `passkeyRemovals` (any number: `removed`, told at least once of the latest 64 gone between two settles).
- `passkeyStore`, the credential records' store interface (create unless held, read, change from what it holds), and `passkeyStoreNeeds`.
- Operator section: `user-verification` (default `required`; any other breaks the promise of a new login, `front-compromise-new-authorization`), `pending-lifetime` (default 10 minutes), `max-credentials` (default 10, at most 16).
- `./testing`: `passkeysConfig` (`PasskeysSettings`); `passkeyStoreContract`, the store interface's contract test.

## Invariants
- A key is usable only once active: reserved, its possession shown by an assertion over a request naming it alone (`verifyPending`), its key change committed and taken in with `took`. The reservation's states and the bindings: `registering`'s card; `commit`'s and `remove`'s rules: `records`'.
- No op of passkeys empties a subject's keys: `remove` refuses, in the write deciding it, a removal after which the subject holds no key.
- `settle` is run by whoever took in an end of a key change: its writer, or a replica whose tending ended one; a boundary's take-in is no such end, so a replica runs it whenever its `tend` stepped one record or more (for `passkey-reset` and the key management package). From the applied state alone and idempotent (`kept`'s card). Until it runs after a `took`, a new key carries no mark.
- The witness's mark is set for a key generation, replacing one of a generation before. Every settle withdraws marks of generations before the current; one that sets a mark reads the keys again after, and withdraws below a generation moved meanwhile. So a mark a late settle set across a boundary goes by that settle's read again, and one a settle stopped before that read goes at the next settle.
- `assert` takes only a credential its request named, where it named any (WebAuthn §7.2). A store that cannot tell is unavailable, never a refusal.
- A passkey witness composed with no witnessing, or two witnessings, refuse boot; so does `registrations` where no writer registers the key change's kind. Composed by hand with neither, the keys alone tell; through `combinations`, `passkey-witnessing` comes with it and refuses boot without one witness.
- Its marks assume the frames' store gives back, after a loss, the key generation the log holds, by taking it in again: a mark of a generation later than the one read is never withdrawn.

## Data
- Its part of each subject's flow, in the frames' store: the keys and the notices of keys gone (written by the Step), the reservation, and what the last settle told of; an erasure boundary empties the keys.
- Credential records by credential id, kept without end in the passkey store. After a subject's erasure, the binding to its subject and the count remain, as the log keeps the key on the subject's flow; the details (handle, transports, backup state, label, time) go at the settle that tells of the key gone, so of the latest 64 keys taken off between two settles alone: an older one keeps its details.

## Depends on
- `kernel`, `promises` (the stances its takers declare), `transparency` and `transparency-wire` (the frame, the kinds, the owners, flows), `authority-rules` (the state's schema, taken by internal module `records`), `webauthn` (the ceremonies, the credential's form), `passkey-witness` (whether a witness is composed).

## Vocabulary
- key: a credential the subject's flow state holds active. reservation: a key's registration in progress, one per subject. binding: a credential record's subject.
