# code-grant

## Responsibilities
- Holds authorization codes, each bound to its approval's root and to the binding the authorization asked for ahead (`dpop_jkt`), and redeems them at the token endpoint (the `authorization_code` grant) as one bundle rooted there.
- Voids a code that comes again, or whose session ends midway: the token it gave is revoked, and failed revocations retried.

## Not here
- The decisions up to issuing a code, and the approval it is issued from (`authorize`, `approvals`). The token format and how tokens are revoked (`tokens`). Recording the bundle on the log, under its start (`token-endpoint`).
- Making the ID token (`idTokens`' contributor, `oidc`). With none composed, a code asking one is answered `invalid_scope`, never redeemed for an access token alone.
- Founding and ending a refresh family (`families`' contributor, `refresh`).

## Offers
- `codes`, for `authorize` only:
  - `issue`: client, redirect URI, PKCE challenge, nonce, scope, audience, session handle, subject, optional acr met, and the binding asked for ahead → code, 32 random bytes in base64url.
    - It checks again the session enters at use with that subject, the client may use the grant with that scope and audience, the challenge's shape, and that an `openid` code has its nonce; the authentication context comes from the session.
  - `root` (code, reference, the approval's facts: `esig`, `apr`, `approvedAt`, required for an `openid` code, else `TypeError`; and its statement's hash, which a family rests on): sets them once, on an unused code without a root (`set`, also for the same root again); `refused` otherwise.
  - `digestOf` (a code) → its SHA-256 in base64url, never the code; `lifetimeMs`, how long a code lives; `issuesIdTokens`, whether an ID token is made, for `openid` to be refused before a code asks one.
- A session closed since it was read throws `Unavailable`, for the caller to answer as it can; any other contradiction is a `TypeError`. `challengeShape` is offered for a request to be checked by.
- Extension point `idTokens` (at most one; two refuse boot): `part` (an `IdTokenRequest`: the code's subject, client, nonce, amr, acr, scope, session handle, its digest as `code`, and its approval's facts) → the ID token as a part of the redemption's bundle (`grants`' `BundlePart`), its reads made before the bundle starts.
- Extension point `families` (at most one): `part` (a `FamilyRequest`: the code's facts, its binding and its statement's hash) → the family as a part of the redemption's bundle, or `refused` (used up, `invalid_grant`); `revoke` (a code's digest, and its subject) ends the family its redemption founded, or founds later.
- Extension point `redemptionHooks` (keyed): `pin` (the redemption, the code's digest as `digestOf` gives it; its subject) before the token is issued, `redeemed` (redemption, subject, scope, the token's id and end) once it passed every check. A hook that fails voids the code.
- The `authorization_code` grant (`codeGrantType`, taking its audience from the request) to `grants`' grant extension point.
- Store interfaces (`codeStore`, `redemptionRecords`, `voidList`), their needs (`codeStoreNeeds`) and `storedRecordMaxMs` (internal module `store`), wired by the assembly; their `erase` and `migrate` back the eraser `code-grant` (`erasure`).
- Operator section: `code-lifetime` (10s–60s, default `60s`), `sweep-interval` (retry of failed revocations, 1s–1h, default `30s`). Times are written with their unit; a bare number is refused.
- `./testing`: `codeGrantConfig`; `codeStoreContract`, the store interfaces' contract test for every implementation.

## Invariants
- A code is used up before it is checked, by a version-compared rewrite, so two uses at once count as reuse. A wrong verifier, client, redirect URI or binding uses it up; a malformed request does not. The verifier is compared in constant time.
- A code is redeemed only with a proof by the key its authorization asked for ahead, and one that asked for none only with no proof (`sender-binding`'s `sameBinding`): the token holds the code's binding and none other. A redemption that fails leaves the code used up; the person logs in again.
- Every refused code is `invalid_grant` with the same description. A session that does not enter at use (closed, or its subject revoked) is refused, and checked again after issuing: so meanwhile, the code is voided.
- The audience asked (`grants`' `target`, within the code's), then the issuance policies, are asked before the code is used up, only for its client, redirect URI, verifier and binding (a refusal leaves it unused), and again when issuing (a refusal then leaves it used up, giving nothing). The access token carries the code's amr, authentication time (or that it is not known) and acr, from the code's session; it ends no later than that session.
- A redemption issues one bundle under the code's root's reference, carried unread, by its code (`via` `code`, with its digest): its access token, its ID token where the scope has `openid` (`id_token`), and a refresh family for a client allowed the refresh grant, of a code rooted with its statement (`refresh_token`). A code with no root set is used up, issuing nothing.
  - A family the token endpoint left out, its approval's key no longer live (V24), is no `refresh_token`: the RP is answered its access token, and its ID token where asked, alone.
- A code is voided (`voiding`) when it comes again, its own record there or ended, or when its session closes while its token is made: its family ended, its token revoked.
- Boot is refused where access tokens cannot be revoked, and where nothing contributes to `grants`' session issuances: its tokens are issued from the code's session and must be recorded there, so that a logout ends them.

## Data
- Codes until their expiry, redemption records for `storedRecordMaxMs`, the void list until each code is settled: in the places `store` declares, with their needs.

## Depends on
- `kernel`, `session`, `clients`, `client-allowance`, `tokens`, `grants`, `issuer`, `sender-binding`, `erasure-extensions`

## Vocabulary
- root: the record a code's chain roots in, its approval's, named by a reference code-grant never reads.
