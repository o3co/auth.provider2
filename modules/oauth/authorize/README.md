# authorize

## Responsibilities
- Starts and finishes a person's login at the Core (② and ⑤⑥, internal modules `start` and `finish`): reads the login's request from its source, verifies the JAR as its client's, checks its redirect URI and `prompt`, reserves the JAR's one use (A20), and has `approvals` sign the statement T over the JAR's items and the screen's keys.
- At the finish, uses the person's assertion over T, judges the issuance, opens the session and has `code-grant` make a code, rooted in the approval's record before its completion is answered.
- Owns the JAR reservations' store interface and its needs, and the extension points where a request comes from and how a person with no passkey is answered.

## Not here
- T, its signature, challenge and use, and the completion: `approvals`. T's items and the rule that makes them from a JAR: `sdk-core-wire`. The client's keys and a JWT's signature: `client-assertion`. Matching a redirect URI: `redirect-uris`.
- The login screen and its page (the deployment's, static), and the redirect back to the client (the screen's). A request by `request_uri`: the module contributing that source (PAR).
- `dpop_jkt`: filled by `approval-binding`. What a person with no passkey is offered: the module contributing `withoutPasskey`.

## Offers
- `POST /login/finish` (`loginFinish`: JSON of `statement` and `assertion`, its JSON text as sent) → `200` `{ sealed: { enc, ct } }`, the completion sealed to the screen; or `invalid_request`, `access_denied`, `invalid_scope`, `invalid_client`, `temporarily_unavailable`. Counted per source as the start is.
- `POST /login/start` (`front-core-wire`'s `loginStart`: JSON of `clientId`, the request's fields, `eEnc`, `eSigX`, `eSigY`) → `200` `{ statement, challenge, create }`; or an OAuth error: `invalid_client` (`401`), `rate_limited` (`429`), `temporarily_unavailable` (`503`), any other `400` (`invalid_request`, `invalid_request_object`, `invalid_target`, `login_required`, and the word a request source names). Starts are counted per source (`requests` in `window`).
- Extension points `requestSources` (keyed by name: a start's fields → the JAR, a refusal in its own words, or none; `request`, by value, is its own) and `withoutPasskey` (at most one: whether the screen may offer `create()`, a hint outside T's signature that whoever registers a key judges again; with a sign-up offered, also its permission, kept on T and never judged again; with none, it may not).
- Extension point `signUpOffers` (at most one, its module's name): with one, a T whose screen may offer `create()` allows its sign-up (F1), which that module continues; with none, no T does.
- `jarReservations`, the store interface (create unless held, read, change from what it holds), and `jarReservationsNeeds`.
- Contributions: `redirect-uris`' client metadata section to `clients` and its document copy to `client-documents`; the authorization's items but `dpop_jkt` to `approvals`' `statementItems`; its stance.
- To `acr`'s `amrSources`: `authorize.passkey`, amr `pop` and `user` (internal module `finish`).
- To `issuer`'s metadata: `authorization_endpoint` (the screen's URL), `response_types_supported` (`code`), `response_modes_supported` (`form_post`), `code_challenge_methods_supported` (`S256`), `require_signed_request_object`, `request_parameter_supported`, `authorization_response_iss_parameter_supported`.
- Operator section: `screen-url` (https), `jar-max-lifetime` (default 10 minutes), `requests` and `window` (default 30 a minute per source), `clock-skew` (default 30 seconds).
  - A session's length is `refresh.lifetime` (O27): `delegation-lifetime`, still written, refuses boot.
- `./testing`: `authorizeConfig` (`AuthorizeSettings`), and `jarReservationsContract`, the store interface's contract test.

## Invariants
- A login is started only by a JAR its client signed (`typ` `oauth-authz-req+jwt`, under `client-assertion`'s algorithms, clock skew and longest lifetime), its `iss` and `client_id` the client, its `aud` this issuer, with a `jti` and an `exp` not past and at most `jar-max-lifetime` away; exactly one request source answers each start.
- A JAR starts one login (A20, internal module `jar`): the same JAR with the same screen keys is answered the same T, made by one call at a time; with other keys, or another JAR under its `jti`, it is refused. Its reservation outlives the JAR's expiry by the clock skew, the margin between replicas' clocks.
- Boot is refused where an item every T carries is filled by no module (`dpop_jkt` with no `approval-binding`), or two modules answer a person with no passkey, or two offer a sign-up, or one does with no answer to a person with no passkey.
- What a code needs is checked before T is made, and again before the session opens (internal module `code-needs`), so nothing a code needs fails once the person tapped. A JAR whose `claims` is malformed or asked without `openid` is refused before T (`invalid_request_object`, internal module `claims`).
- The redirect URI is one the client registered, by `redirect-uris`' rule, before anything is reserved or signed.

## Data
- Each JAR's reservation, by its client and `jti`: the digest of the start that used it and the answer made, until the JAR's expiry and the clock skew.

## Depends on
- `kernel`, `http` (the routes), `clients` and `client-documents` (the client, its section), `client-assertion` (`verifySignedBy`), `client-allowance`, `grants` (`targetRules`), `redirect-uris`, `approvals`, `code-grant`, `session`, `tokens` (the policies), `sender-binding` (the binding asked for ahead), `issuer`, `rate-limit`, `promises` (its stance), `sdk-core-wire`; `zod`.
- `oidc` (the `claims` parameter's reading) and `claims-selection`; `acr` (`amrSources`, the acr a passkey's login meets); `refresh` (`delegation`, a session's length), which must be composed.

## Vocabulary
- start: ②, a login's first request from the screen. JAR: the client's signed request (RFC 9101). reservation: a JAR's one use. source: where a start's JAR comes from.
