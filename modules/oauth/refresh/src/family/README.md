# family

Internal module of `refresh`: founding a family with a code's redemption, and ending the one a code founded.

## Responsibilities
- Reads a family's root before the redemption's bundle starts, signs its token with the bundle's record, and keeps it once the bundle is taken in.

## Not here
- When a family is founded (`code-grant`). The bundle, its receipts and its taking in (`token-endpoint`). Using a family (`grant`).

## Offers
- `founding` (`FoundingParts`: the records, `approvals`' `rootOf`, `passkeys`' `publicKeyOf`, `keys`' generation, `claims-selection`'s `follow`, the delegation's length, the clock, a secret, `rooted`'s `list`, `audit`) → `code-grant`'s `FamilyMaker`. `foundingIn`, `foundingTakes`: the same over the composition.

## Invariants
- `part` reads, before the bundle starts: the approval's statement, assertion and credential; the key's public key and registration record, active and the subject's; the generation whose ring signed the statement (this one or the one before); and that the index holds no family for the code's key.
  - One gone, or the key held, is `refused`, the code used up (`invalid_grant`). The key held is recorded (`refresh.key_bound`: subject, client, binding, thumbprint), here or where `commit` finds it claimed first; refused here, the client is told so (`told`: the DPoP key is bound to another refresh family), its own key's use; found at `commit`, it is told nothing (unavailable), then `invalid code` if it tries again.
- `sign` throws where the bundle's record id names no token the Front's wire carries (over 63 bytes): the redemption answers no token, nothing kept here. A root key removed after the founding ends the family by `rooted`, as `passkeys` tells it; one not told is caught at the next refresh, the flow's state having dropped the family.
- The family's end is its statement's issue and the delegation's length (O27). Its record keeps what its root does not tell: the credential's registration and public key, the subject, the authentication time, the end, the secret's hash, the Core generation that signed the statement.
- `commit`, once the bundle is taken in (V12): the family kept by its bundle record's id, linked to its code, its key claimed by the index's one create (never overwritten, kept to the family's end), its claims followed. Its code voided meanwhile, its key claimed by another family first, or a failure midway, ends it at once, unavailable: its token is never answered, the bundle on the log alone (A40).
  - Listed under its subject and root key (internal module `rooted`), then its root key read again: one removed meanwhile ends it.
- The registration's record is kept, not yet compared with the flow's state (`chain`).
- `revoke` (a code's digest) ends the family that code founded, or marks the code so the family it would found is ended as it is kept.

## Depends on
- `approvals`, `passkeys`, `keys`, `claims-selection`, `code-grant` (the maker's contract), `grants` (the part), `audit`, `kernel`; the package's records and store.
