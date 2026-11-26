# statement

Internal module of `approvals`: issuing statements, using each once, and reading their records.

## Responsibilities
- Signs a statement of one purpose over its items, under the common fields (the wire version it writes, the latest `sdk-core-wire` speaks; issuer, id, times, the screen's keys, a nonce but for T), and records it by its hash.
- Uses a statement once, and answers the approval from its record.
- Reads a statement's record for its callers: a used one's approval, a creation's record, what a used authorization rests on, a used passkey-add as its key change takes it; and marks an authorization's completion kept as gone out, giving it from then on.

## Not here
- Continuations (`continuation`). Making a completion, and the flow (`completion`).

## Offers
- `statementsOver` (`StatementParts`) → `issue`, `use`, `usedOf`, `creationOf`, `rootOf`, `passkeyAddOf`, `keptChangeOf`, `signUpOf`, `signUpSubject`, `completionOf`, `publish`, as `approvals` offers them:
  - `issue` (purpose, items, the screen's `eEnc` and `eSig`, the key it is counted by; a T's stages its owner allows, `continues`; the longest it may be, `fits`) → the statement (`approval+jwt`), its hash, its challenge; or refused: `items` (a screen key of no point or no thumbprint among them), `limited`, `busy`, `withdrawn`, `long` (its length, known from the header, the payload and the signature's size before signing, over `fits`: before it is counted, never signed or kept).
  - `use` (statement; an assertion's JSON text as sent, or a possession's verification) → the approval (hash, purpose, items, subject, credential and the key's registration's record id, or the verification; when used, its `eSig`'s thumbprint `esig`); or refused. A passkey-add's and a passkey-manage's items are none.
  - `usedOf` (hash) → a used statement's approval, with its statement's issue time, `completed` once its completion is kept. `creationOf` (hash) → a creation's record until it expires.
  - `rootOf` (hash) → what a used authorization rests on, for a refresh family to check again: its statement, the assertion as received, its credential; none once its record is gone.
  - `passkeyAddOf` (hash) → a used passkey-add: its statement, the assertion as received, the key's subject, credential and registration, the screen's keys, and the statement's use-once mark; none past its expiry, where this generation's ring does not verify it, or for a record used before it held the registration.
  - `keptChangeOf` (a possession's hash) → what its key change was made of, to make its stage again once placed: the creation as kept, the continuation that made the possession (its number, body as received and signature), and the creation's evidence (the used passkey-add, or the sign-up's T as signed).
    - Read while the records are kept, a minute past each statement's expiry, whatever expired, while this generation's ring verifies the possession; none for a possession not used, one its creation's last continuation did not make, or a passkey-add another subject used.
  - `signUpOf` (T's hash) → its sign-up as kept (F1): its statement, the subject, the creation its step answered and the credential its key change kept, each once kept; none where none began, or this generation's ring does not verify it. `signUpSubject` (T's hash, subject) → the subject kept for its begun sign-up, the first one written; none where none began.
  - `completionOf` (hash) → the completion kept, as `complete` answered it, once `publish` marked it gone out; none before. `publish` (hash): marks it so, once its caller let it go (an authorization's code rooted first).
- `declaredOf` (the declarations, a refusal) → each purpose's declared names. `statementMark` (a statement's id) → its use-once mark, as `authority-rules`' fold names it. `itemNames`, `itemsIn`, `challengeOf`, `sha256`; the record's shape (`recordOf`, `stored`).

## Invariants
- `issue` checks the items against the declared names and the purpose's schema, and the screen's `eEnc` as a P-256 point, before anything is counted or signed; counts all statements and the caller's key in `issue-window`; refuses past `max-concurrent` signings in this process.
- A creation's challenge is for `create()`, any other's for `get()`.
- The record is kept a minute past the statement's expiry, so a late use reads as expired.
- A use writes once, from issued to used, holding what used it and when: an assertion's subject, credential, the key's registration as `passkeys` answered it, and JSON text as sent, or a verification. A record used before it held the registration names none. Its answer is the approval only where the record holds that same evidence; any other is `used`.
- A T whose sign-up began is used only once its key change kept the credential it registered (`signUp.credential`), and only by that credential's assertion, of the subject made for it where one is kept: refused `used` before the assertion is asked (by the credential it names), after it, and in the write that uses it.
- A record of another shape is read as a store that cannot tell: unavailable.
- A use reads the record by the hash of the bytes presented, and takes them only where they are the bytes recorded and the Core's ring of this generation verifies them.

## Depends on
- `keys` (`prepare`, `sign`), `passkeys` (`assert`), `rate-limit` (`hit`), `sdk-core-wire` (schemas, canonical text, the challenge's input).
