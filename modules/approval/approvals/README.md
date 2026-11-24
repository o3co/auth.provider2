# approvals

## Responsibilities
- Holds the statements a person approves with a passkey, for the IdP's own operations alone: it signs each by the Core's ring, records it, derives its challenge, uses it once, takes the screen's continuations, and answers an authorization's completion, signed and sealed.
- Owns the statements' store interface and its needs, the authorization's kind of operation on the subject's flow (`approval`), and the flow state's approvals and use-once marks (`approvals`, `consumed`).

## Not here
- The statements' schemas, the challenge's and a continuation's inputs, the completion's form and the HPKE suite: `sdk-core-wire`. Signing, verifying and sealing: `keys`.
- The assertion's ceremony, the keys and a pending key's verification: `passkeys`. The frame, leases, takers and abandonments: `transparency`. What a record changes, and its judgment: `authority-rules`.
- What an item means and who asked it: the module that fills it. The code: the authorization's owner, which gives it to `complete`.
- Purposes `passkey-add` and `passkey-manage`, and a continuation of any stage but `register`: not in `sdk-core-wire`'s schema, so none is signed. The completion's receipt of its record (A35): not in the completion's schema, so the completion carries none.

## Offers
- `approvals`, taken only by a module standing on the promises (`promises`' `stances`):
  - `issue` (purpose, items, the screen's `eEnc` and `eSig`, the key it is counted by) → the statement (`approval+jwt`), its hash, its challenge; or refused: `items` (a screen key of no point, or an `eSig` of no thumbprint, among them), `limited`, `busy`, `withdrawn`.
  - `use` (statement; an assertion's JSON text as sent, or a possession's verification) → the approval (hash, purpose, items, subject and credential or the verification, when used, its `eSig`'s thumbprint `esig`); or refused.
  - `continue` (hash, sequence number, body, the screen's signature, its step) → continued with what the step answered (`again` where another call took it first); or refused, `pending` while another call holds its step.
  - `complete` (hash, code) → the completion sealed to `eEnc` (HPKE's `enc` and ciphertext) and the id of the approval's record on the flow, the reference the code's chain roots in, with its `recordRef` (`ref`, an ID token's `apr`) and the log's acceptance time (`acceptedAt`, its `auth_time`); or refused.
  - `completionOf` (hash) → the completion kept, as `complete` answered it, once `publish` marked it gone out; none before. `publish` (hash): marks it so, once its caller let it go (an authorization's code rooted first).
  - `usedOf` (hash) → a used statement's approval, with its statement's issue time, `completed` once its completion is kept.
- Extension point `statementItems` (purpose, the item names it fills, by whom): the purposes are `authorization`, `creation` and `possession`.
- `approvalStore`, the statements' store interface (create unless held, read, change from what it holds), and `approvalStoreNeeds`. `approvalPart`: its part of each subject's flow, which its wiring binds.
- Operator section: `statement-lifetime` (default 5 minutes), `issue-limit`, `issue-total` and `issue-window` (default 30 a minute per key, 100 000 a minute in all), `max-concurrent` (default 64 signings at once).
- `./testing`: `approvalsConfig` (`ApprovalsSettings`), and `approvalStoreContract`, the store interface's contract test.

## Invariants
- Purposes and items are closed: a purpose is one `sdk-core-wire` names a schema for, an item one its schema names and one module declared it fills. Boot refuses a name no schema holds, or one two modules fill; `issue` refuses an item no module declared, or one the schema refuses.
- A statement is used once, by one write from issued (internal module `statement`), and only while the Core's ring of this generation verifies it. An authorization's is used only by an assertion over its challenge that verified its user, whatever `passkeys`' section lets through; the same evidence again answers the same approval. A possession's verification is taken as given: that it showed a verified user is its caller's to check, from `verifyPending`.
- A purpose's owner takes the items from the used record (`usedOf`, or `use`'s answer), never from a later request.
- An authorization's completion is signed only after its approval is taken in on the subject's flow as its owner's `took` (internal module `completion`).
- Its op is never taken over, as only its owner holds the code: an orphan is marked and abandoned. Only one abandoned before its stage was placed can be completed again, by a later `complete`; one whose stage was placed is taken in as done, its statement used, and gives no completion. Any other end, a lost answer or a fault before the completion is kept gives none, ever: the person approves again.
- A continuation's step is run by the one call that took its sequence number, and its answer kept with it before the next number is taken; it is run again only where that call's hold lapsed with none kept (internal module `continuation`).
- Statements and completions are signed by the Core's ring, apart from the authority's: under `approval+jwt` and `completion+jwt`, their items under one member, never as a token's claims.

## Data
- Each statement's record, by its hash, from its issuing to a minute past its expiry: its purpose, bytes, the screen's keys, how far it went, the subject, credential and assertion that used it, the last continuation and the completion.
- Its part of each subject's flow, in the frames' store: the state's approvals and use-once marks.

## Depends on
- `kernel`, `keys` (the Core's ring, sealing), `passkeys` (the assertion), `promises` (its stance), `rate-limit` (issuing counted), `issuer` (the statements' issuer), `sdk-core-wire` (the schemas and inputs), `transparency` and `transparency-wire` (the kind, the owner, the flow, the log's digest); `zod`.

## Vocabulary
- statement: what a person approves, signed for one purpose. T: an authorization's statement. item: a statement's field of its purpose.
- approval: a statement used, with what used it. continuation: the screen's next message in a ceremony, signed with its `eSig`. completion: the authorization's answer to the screen.
