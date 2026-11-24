# code-grant

## Responsibilities
- Holds authorization codes, each bound to its approval's root and to the binding the authorization asked for ahead (`dpop_jkt`), and redeems them at the token endpoint (the `authorization_code` grant) as one bundle rooted there.
- Voids a code that comes again, or whose session ends midway: the token it gave is revoked, and failed revocations retried.

## Not here
- The decisions up to issuing a code, and the approval it is issued from (`authorize`, `approvals`). The token format and how tokens are revoked (`tokens`). Recording the bundle on the log, under its start (`token-endpoint`).
- Making the ID token (`idTokens`' contributor, `oidc`). With none composed, a code asking one is answered `invalid_scope`, never redeemed for an access token alone.
- Open for a later stage, in the bundle and the voiding: a refresh family, and its revocation on a reuse.

## Offers
- `codes`, for `authorize` only:
  - `issue`: client, redirect URI, PKCE challenge, nonce, scope, audience, session handle, subject, optional acr met, and the binding asked for ahead → code, 32 random bytes in base64url.
    - It checks again the session enters at use with that subject, the client may use the grant with that scope and audience, the challenge's shape, and that an `openid` code has its nonce; the authentication context comes from the session.
  - `root` (code, reference, the approval's facts for an ID token: `esig`, `apr`, `approvedAt`, required for an `openid` code, else `TypeError`): sets them once, on an unused code without a root (`set`, also for the same root again); `refused` otherwise.
  - `digestOf` (a code) → its SHA-256 in base64url, never the code; `lifetimeMs`, how long a code lives; `issuesIdTokens`, whether an ID token is made, for `openid` to be refused before a code asks one.
- A session closed since it was read throws `Unavailable`, for the caller to answer as it can; any other contradiction is a `TypeError`. `challengeShape` is offered for a request to be checked by.
- Extension point `idTokens` (at most one; two refuse boot): `part` (an `IdTokenRequest`: the code's subject, client, nonce, amr, acr, scope, session handle, its digest as `code`, and its approval's facts) → the ID token as a part of the redemption's bundle (`grants`' `BundlePart`), its reads made before the bundle starts.
- Extension point `redemptionHooks` (keyed): `pin` (the redemption, the code's digest as `digestOf` gives it; its subject) before the token is issued, `redeemed` (redemption, subject, scope, the token's id and end) once it passed every check. A hook that fails voids the code.
- The `authorization_code` grant (`codeGrantType`, taking its audience from the request) to `grants`' grant extension point.
- Store interfaces (`codeStore`, `redemptionRecords`, `voidList`), their needs (`codeStoreNeeds`) and `storedRecordMaxMs`.
  - Wired by the assembly, never shown what a record holds: codes by a name made from the code, for its subject (rewrite from the current contents); each redemption record by that name (create, read, rewrite; `redemption-record`); the void list (add, done, go through in order).
  - Their `erase` and `migrate` back the eraser `code-grant` (`erasure`).
- Operator section: `code-lifetime` (10s–60s, default `60s`), `sweep-interval` (retry of failed revocations, 1s–1h, default `30s`). Times are written with their unit; a bare number is refused.
- `./testing`: `codeGrantConfig`; `codeStoreContract`, the store interfaces' contract test for every implementation.

## Invariants
- A code is used up before it is checked, by a version-compared rewrite, so two uses at once count as reuse. A wrong verifier, client, redirect URI or binding uses it up; a malformed request does not. The verifier is compared in constant time.
- A code is redeemed only with a proof by the key its authorization asked for ahead, and one that asked for none only with no proof (`sender-binding`'s `sameBinding`): the token holds the code's binding and none other. A redemption that fails leaves the code used up; the person logs in again.
- Every refused code is `invalid_grant` with the same description. A session that does not enter at use (closed, or its subject revoked) is refused, and checked again after issuing: so meanwhile, the code is voided.
- The audience asked (`grants`' `target`, within the code's), then the issuance policies, are asked before the code is used up, only for its client, redirect URI, verifier and binding (a refusal leaves it unused), and again when issuing (a refusal then leaves it used up, giving nothing). The access token carries the code's amr, authentication time (or that it is not known) and acr, from the code's session; it ends no later than that session.
- A redemption issues one bundle under the code's root's reference, carried unread, by its code (`via` `code`): its access token, and its ID token where the scope has `openid` (`id_token`). A code with no root set is used up, issuing nothing.
- A record that vanished during a redemption is refused and never written back (the code would be unused again). A record of a format or shape not known is a code that cannot be used: refused (not unavailable), or logged and removed from the list.
- A code is voided (`voiding`) when it comes again, its own record there or ended, or when its session closes while its token is made. A reuse marks the code itself, which the redemption reads again after issuing: a mark there, or the code ended, voids its token, even one that came before any redemption record. Issuing that fails leaves it used up, giving nothing.
- A configuration that cannot revoke access tokens refuses boot.
- Boot is refused where nothing contributes to `grants`' session issuances: its tokens are issued from the code's session and must be recorded there, so that a logout ends them.

## Data
- Codes: a record per code name until its expiry. Redemption records: each for `storedRecordMaxMs` (`kernel`'s clock; syncing hosts is the deployment's). The void list: until each code is settled.
- Needs: no eviction (tokens to revoke would be lost), a crash survived, no rollback on failover (a used code would come back), names derived from the code.

## Depends on
- `kernel`, `session`, `clients`, `client-allowance`, `tokens`, `grants`, `issuer`, `sender-binding`, `erasure-extensions`

## Vocabulary
- root: the record a code's chain roots in, its approval's, named by a reference code-grant never reads.
