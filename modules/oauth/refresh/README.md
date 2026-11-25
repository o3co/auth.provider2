# refresh

## Responsibilities
- Owns rooted refresh (proposal 3.9, C4): refresh families founded with a code's redemption, each bound to its authorization's key and rooted in its approval, never rotated, checked again from their root at every refresh.
- Holds the delegation's length (O27): a family's end, and its session's, from its statement's issue.

## Not here
- When a family is founded, and ending one when its code comes again (`code-grant`, through `families`). Recording a bundle, and a refresh's rotation on the flow's state (`token-endpoint`, `authority-rules`).
- A family's root: its approval (`approvals`), its key (`passkeys`), the assertion's check (`webauthn`), the statement's ring (`keys`). A family's claims (`claims-selection`).
- A family ended by its key's removal or a reset: the flow's fold drops it, and a refresh of it is refused as its op is decided (`family`).

## Offers
- A contribution to `code-grant`'s `families` (internal module `family`) and the `refresh_token` grant to `grants` (internal module `grant`).
- A `token-revocation` revocable kind `refresh_token`: only its client revokes it, with its family.
- Contract `delegation` (`lifetimeMs`), which `authorize` reads for a session's end.
- Store interface `familyRecords` (create for a subject, read, change from what it holds; `erase` and `migrate` together or neither, a part refusing boot) and `familyRecordsNeeds`; `./testing`: `refreshConfig`, `familyRecordsInMemory`.
- A contribution to `erasure-extensions`' erasers: `refresh` (internal module `erasure`), every record keeping its subject.
- Operator section: `lifetime`, the delegation's length (`5m`–`1y`, default `1d`).
- Its stance: `front-compromise-new-authorization` holds: a family rests on a passkey's approval, its token on the authorization's key.

## Invariants
- A refresh token is `<family>.<secret>`: the family's id (its bundle record's, base64url) and 32 random bytes; the family keeps the secret's SHA-256 alone.
- A family is bound to its authorization's key (`dpop_jkt`): one family a key (Q27), the key held until that family's end, revoked or not; its token used only with a proof by that key. Bound, it is never rotated: each refresh answers the same token.
- A family lives no longer than its delegation (its statement's issue and `lifetime`, the same end as its session's) nor its session: each refresh asks the session to enter, before issuing and again after, so a logout ends it, even one racing a refresh, its record and key kept to their end. Boot is refused where no module records its tokens to their session (`grants`' `sessionIssuances`).
- Ending a family (revoked, its code voided, its key removed) revokes no access token it gave: each ends with its lifetime, as after a reset (proposal 3.9).
- Every refusal of a token is the same `invalid_grant`; a store failure is unavailable, never a negative verdict.
- Its access tokens carry the amr, authentication time and acr of its redemption, its scope narrowed only within the family's (`offline_access` never part of it), its audience within the family's.

## Depends on
- `kernel`, `code-grant`, `grants`, `token-revocation`, `tokens`, `promises`, `erasure-extensions`; the internal modules' own.

## Vocabulary
- family: a code redemption's delegation, its one refresh token. root: the approval it rests on.
