# refresh

## Responsibilities
- Owns rooted refresh (proposal 3.9, C4): refresh families founded with a code's redemption, each bound to its authorization's key and rooted in its approval, never rotated, checked again from their root at every refresh.
- Holds the delegation's length (O27): a family's end, and its session's, from its statement's issue.

## Not here
- When a family is founded, and ending one when its code comes again (`code-grant`, through `families`). Recording a bundle, and a refresh's rotation on the flow's state (`token-endpoint`, `authority-rules`).
- A family's root: its approval (`approvals`), its key (`passkeys`), the assertion's check (`webauthn`), the statement's ring (`keys`). A family's claims (`claims-selection`).
- Which families a root key's removal or a reset ends on the log: the flow's fold drops them, and a refresh of one is refused as its op is decided.

## Offers
- A contribution to `code-grant`'s `families` (internal module `family`) and the `refresh_token` grant to `grants` (internal module `grant`), declaring `keyHold` `family`.
- A `token-revocation` revocable kind `refresh_token`: only its client revokes it, with its family.
- A contribution to `passkeys`' `passkeyRemovals` (internal module `rooted`): a root key (its approval's passkey) removed ends the families rooted in it here, a subject emptied all of its (Q46). It holds `passkeys`, which collects it as it builds, by a late reference.
- A contribution to `transparency`'s `stateOwners`: the state's families on a subject's flow, in its part `familiesPart`, which its store wiring binds (internal module `state`).
- Contract `delegation` (`lifetimeMs`), which `authorize` reads for a session's end.
- Store interface `familyRecords` (create for a subject, read, change from what it holds; `erase` and `migrate` together or neither, a part refusing boot) and `familyRecordsNeeds`; `./testing`: `refreshConfig`, `familyRecordsInMemory`, `familiesOwning` (its owner of the families alone, for a composition without refresh).
- A contribution to `erasure-extensions`' erasers: `refresh` (internal module `erasure`), every record keeping its subject.
- Operator section: `lifetime`, the delegation's length (`5m`–`1y`, default `1d`).
- Audit event `refresh.key_bound` (`./audit-events`): a code's redemption founded no family, its key bound to another family (Q27); its subject, client, the binding's kind and the key's thumbprint.
- Its stance: `front-compromise-new-authorization` holds: a family rests on a passkey's approval, its token on the authorization's key.

## Invariants
- A refresh token is `<secret><family>`, nothing between: 32 random bytes and the family's id (its bundle record's), each base64url; the family keeps the secret's SHA-256 alone.
- A token fits the Front's wire's `refreshToken` (front-core-wire): base64url alone, at most 128 characters; a family id of more than 63 bytes, which would not fit, gives no token (thrown, after the bundle is on the log: the redemption answers no token, its code used up).
- A family is bound to its authorization's key (`dpop_jkt`): one family a key (Q27), the key held until that family's end, revoked or not; its token used only with a proof by that key. Bound, it is never rotated: each refresh answers the same token.
- A family lives no longer than its delegation (its statement's issue and `lifetime`, the same end as its session's) nor its session: each refresh asks the session to enter, before issuing and again after, so a logout ends it, even one racing a refresh, its record and key kept to their end. Boot is refused where no module records its tokens to their session (`grants`' `sessionIssuances`).
- Ending a family (revoked, its code voided, its root key removed) revokes no access token it gave: each ends with its lifetime, as after a reset (proposal 3.9).
- A root key's removal ends its families here as the log's fold drops them (DelDrop, NextGen); it frees no DPoP key (`dpop_jkt`) bound to them, which Q27 holds to each family's end. A family past its rooted list's 64, or a removal not told, is held by the log's rules and its end alone.
- Every refusal of a token is the same `invalid_grant`; a store failure is unavailable, never a negative verdict.
- Its access tokens carry the amr, authentication time and acr of its redemption, its scope narrowed only within the family's (`offline_access` never part of it), its audience within the family's.

## Depends on
- `kernel`, `audit`, `code-grant`, `grants`, `token-revocation`, `tokens`, `promises`, `erasure-extensions`, `transparency` (`stateOwners`); the internal modules' own.

## Vocabulary
- family: a code redemption's delegation, its one refresh token. root: the approval it rests on.
