# userinfo

## Responsibilities
- Serves OIDC's userinfo: admits the access token a request presents, checks the session it was issued in, and answers `sub` and the claims `oidc` releases for its scope and the selection `claims-selection` kept for the token.
- Declares where it stands on the promises a compromised Front must not break (G1).

## Not here
- The claim table and mapping attributes to claims (`oidc`'s `releasedClaims`). A token's validity (`tokens`) and its holder's proof (`sender-binding`). Whether a session is open (`session`). Which session a token was issued in (`session-tokens`). What a token's request asked beyond its scope (`claims-selection`). How cross-origin requests are answered (`http`).
- Refusing a deployment that requires those promises: `promises`, by its stances.
- Telling a token kept no selection from one whose selection was lost: `claims-selection`'s `forToken` answers none for both, and the claims are then released by the scope alone.

## Offers
- Routes `GET` and `POST /oauth/userinfo`, each counted per source by `rate-limit`'s `requestsPerSource`, the GET declared not to change state and the POST to take requests from other sites; taking cross-origin requests from the operator's origins: a page may send `authorization`, `dpop` and `content-type`, and read `www-authenticate`, `dpop-nonce` and `retry-after`.
- The issuer's metadata `userinfo_endpoint`, on the origin `issuer` names its endpoints on (`endpointOrigin`).
- Two stances (`promises`' `stances`), both breaking: `front-compromise-new-authorization` and `front-compromise-client-token`.
- Operator section: `requests` (per source and window; 1–100000, default 60) and `window` (written with its unit, `1s` to `1d` in whole seconds, default `1m`).
- It opts in: a composition names it to compose it.

## Invariants
- Every request is counted per source before its token is read, whatever scheme it names; one that goes on to a DPoP proof's check is counted by `dpop` too. Past the window, the policy's `429`. A count that cannot be made is the policy's `503` `service_unavailable`, or lets the request through where `rate-limit`'s `fail-mode` is `open`; a source a trusted proxy did not tell is `503` whatever it.
- Many clients behind one source share its count, which may pinch: the operator raises `requests`.
- The token comes from the `Authorization` header only, admitted by `sender-binding`; a body or query `access_token` is never read. A refusal is passed on with its status and challenge; one for a request with no token carries no `error`.
- A token whose scope lacks `openid` is refused `403 insufficient_scope`, challenged in the token's scheme, before its session is read.
- The token's audience is not read: userinfo is the issuer's own resource, answering any token it issued whose session enters. It tells its own tokens by the `openid` scope (OIDC Core §5.3.1); a token's `aud` names its grant's resource (RFC 9068 §4), not the issuer.
- A token issued in no session is refused `401 invalid_token`, whatever grant gave it, and its subject is not told: a client's own token may carry `openid`. 0.x answered it `sub` alone; this is an intended change.
- A token issued in a session is answered its claims only while that session enters at `use` for the token's subject; else (closed, ended, revoked, or another subject's) `401 invalid_token`, challenged in the token's scheme.
- The claims are what `oidc` releases for the token's scope and its kept selection, read with the session's handle: the names it asks beyond the scope, and the constraints on all it releases. The selection is read only for a token whose session enters, and the token's expiry is checked again once it is read: one that ended meanwhile is `401 invalid_token`, never answered without its selection.
- `sub` is always the token's subject, and `sid` is never answered.
- An answer is bound to neither the token nor the request, so the Front can answer any `sub` and attributes: a relying party trusting it, or a party taking it in place of checking the token, trusts the Front that relays it. It stands breaking both promises, declared by itself (it takes no contract whose owner marks its takers); a deployment requiring either is refused boot by `promises`.
- It declares no stance on `core-compromise-contained`: an answer carries no receipt, and a party trusting one is not that promise's receiver.
- Every answer is `no-store`. A check or the claims that cannot tell answer `503 temporarily_unavailable`, never a refusal or a claim: the routes' declared answer, which `http` gives after its warning `http.unavailable` with what failed and the route.

## Data
- None.

## Depends on
- `kernel`, `http`, `issuer` (metadata, the endpoints' origin), `sender-binding`, `tokens`, `session`, `session-tokens`, `claims-selection` (a token's selection), `oidc` (released claims), `rate-limit` (the per-source count), `promises` (its stances)
