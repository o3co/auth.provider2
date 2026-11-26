# approvals

## Responsibilities
- Holds the statements a person approves with a passkey, for the IdP's own operations alone: signs each by the Core's ring, records it, derives its challenge, uses it once, takes the screen's continuations, answers completions.
- Owns the statements' store interface and its needs, the authorization's kind of operation on the subject's flow (`approval`), and the flow state's approvals and use-once marks (`approvals`, `consumed`).

## Not here
- The statements' schemas, the challenge's input, the completion's form and the HPKE suite: `sdk-core-wire`. Signing, verifying and sealing: `keys`.
- The assertion's ceremony, the keys and a pending key's verification: `passkeys`. The frame, leases, takers and abandonments: `transparency`. What a record changes, and its judgment: `authority-rules`.
- What an item means and who asked it: the module that fills it. The code: the authorization's owner, which gives it to `complete`.
- The completion's receipt of its record (A35): not in the completion's schema, so the completion carries none.

## Offers
- `approvals`, taken only by a module standing on the promises (`promises`' `stances`); each offer's asks and answers are its internal module's:
  - `issue`: a statement of one purpose signed and recorded for the screen's keys; longer than `fits`: `long`, unsigned. `use`: a statement used once, by an assertion (an authorization's, a passkey-add's, a passkey-manage's) or a possession's verification (`statement`).
  - `usedOf`: a used statement's approval. `creationOf`: a creation's record. `rootOf`: what a used authorization rests on. `passkeyAddOf`: a used passkey-add as its key change takes it. `keptChangeOf`: what a used possession's key change was made of, to its records' end. `completionOf` and `publish`: an authorization's completion kept, and marked gone out (`statement`).
  - `continue`: a creation's continuation, its step run once and answered again alike. `continueSignUp`: a T's sign-up (F1), the same, on a T its owner allowed. `continueSealed`: a used passkey-manage's sealed `delete` or `rename`, opened here, the same (`continuation`).
  - `signUpOf`: a T's sign-up as kept. `signUpSubject`: the subject made for it, kept once (`statement`).
  - `complete`: an authorization's completion, its approval on the flow first. `completeKeyChange`: a used possession's key-change completion. `completePasskeyAdd`: a used passkey-add's, carrying the creation made for it. `completePasskeyManage`: a passkey-manage's list of keys, for a caller that checked the approving key (`completion`).
- Extension point `statementItems` (purpose, the item names it fills, by whom): the purposes are `authorization`, `passkey-add` and `passkey-manage` (which name no items, so none fills them), `creation` and `possession`.
- `approvalStore`, the statements' store interface (create unless held, read, change from what it holds), and `approvalStoreNeeds`. `approvalPart`: its part of each subject's flow, which its wiring binds.
- Operator section: `statement-lifetime` (default 5 minutes), `issue-limit`, `issue-total` and `issue-window` (default 30 a minute per key, 100 000 a minute in all), `max-concurrent` (default 64 signings at once).
- `./testing`: `approvalsConfig` (`ApprovalsSettings`), `approvalStoreContract`, the store interface's contract test, and `takenOverAfterMs` (internal module `continuation`).

## Invariants
- Purposes and items are closed: a purpose is one `sdk-core-wire` names a schema for, an item one its schema names and one module declared it fills. Boot refuses a name no schema holds or two modules fill; `issue`, an item no module declared or the schema refuses.
- A statement is used once, by one write from issued, and only while the Core's ring of this generation verifies it, by the evidence its purpose takes (internal module `statement`). A T whose sign-up began is used only by the credential its key change kept on it (F1). A purpose's owner takes the items from the used record (`usedOf`, or `use`'s answer), never from a later request.
- An authorization's completion is signed only after its approval is taken in on the subject's flow as its owner's `took` (internal module `completion`).
- Its op is never taken over, as only its owner holds the code: an orphan is marked and abandoned. Only one abandoned before its stage was placed can be completed again, by a later `complete`; one placed is taken in as done, its statement used, with no completion. Any other end, a lost answer or a fault before the completion is kept gives none: the person approves again.
- A continuation's step is run by the one call that took its sequence number, and its answer kept with it before the next number is taken; it is run again only where that call's hold lapsed with none kept (internal module `continuation`).
- Statements and completions are signed by the Core's ring, apart from the authority's: under `approval+jwt` and `completion+jwt`, their items under one member, never as a token's claims.

## Data
- Each statement's record, by its hash, from its issuing to a minute past its expiry (internal module `statement`). Its part of each subject's flow, in the frames' store: the state's approvals and use-once marks.

## Left to you
- No two replicas' kernel clocks differ by more than 2 seconds, at any instant, not only while a call holds a step: another call takes a lapsed hold only 2 seconds past its end (internal module `continuation`).
- Once another call took a hold, no replica's wall clock goes back to its end or before while the call stopped under it may resume, with no bound: one that did would decide beside the call that took it. No clock lifts this; only a fence that is no clock would.

## Depends on
- `kernel`, `keys` (the Core's ring, sealing, opening), `passkeys` (the assertion, the keys' list), `promises` (its stance), `rate-limit` (issuing counted), `issuer`, `sdk-core-wire` (schemas, inputs), `continuation-wire` (a continuation's inputs, the sealed stages), `transparency` and `transparency-wire` (the kind, flow and log's digest); `zod`.

## Vocabulary
- statement: what a person approves, signed for one purpose. T: an authorization's statement. item: a statement's field of its purpose. approval: a statement used, with what used it. continuation: the screen's next message in a ceremony, signed by its `eSig`. completion: an authorization's, a key change's, a passkey-add's or a passkey-manage's answer to the screen.
