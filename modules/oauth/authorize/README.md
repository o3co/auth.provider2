# authorize

## Responsibilities
- Starts and finishes a person's login at the Core (② and ⑤⑥, internal modules `start` and `finish`): reads the login's request from its source, verifies the JAR as its client's, checks its redirect URI and `prompt`, reserves the JAR's one use (A20), and has `approvals` sign the statement T over the JAR's items and the screen's keys.
- At the finish, uses the person's assertion over T, judges the issuance, opens the session and has `code-grant` make a code, rooted in the approval's record before its completion is answered.
- Owns the JAR reservations' store interface and its needs, and the extension points where a request comes from and how a person with no passkey is answered.

## Not here
- T, its signature, challenge and use, and the completion: `approvals`. T's items and the rule that makes them from a JAR: `sdk-core-wire`. The client's keys and a JWT's signature: `client-assertion`. Matching a redirect URI: `redirect-uris`.
- The login screen and its page (the deployment's, static), and the redirect back to the client (the screen's). A request by `request_uri`: the module contributing that source (PAR).
- The wire's words `login_required` and `invalid_request_uri` (`front-core-wire`, which answers them as `server_error` until it holds them), `prompt` in a JAR's envelope and the start's answer's schema (`sdk-core-wire`): until they are there, `prompt=none` reaches the screen as a server error, and a JAR with `prompt` is refused by the screen.
- `dpop_jkt`: filled by `approval-binding`. What a person with no passkey is offered: the module contributing `withoutPasskey`.

## Offers
- `POST /login/finish` (`loginFinish`: JSON of `statement` and `assertion`, its JSON text as sent) → `200` `{ enc, ct }`, the completion sealed to the screen; or `invalid_request`, `access_denied`, `invalid_scope`, `invalid_client`, `temporarily_unavailable`. Counted per source as the start is.
- `POST /login/start` (`front-core-wire`'s `loginStart`: JSON of `clientId`, the request's fields, `eEnc`, `eSigX`, `eSigY`) → `200` `{ statement, challenge, create }`; or an OAuth error: `invalid_client` (`401`), `rate_limited` (`429`), `temporarily_unavailable` (`503`), any other `400` (`invalid_request`, `invalid_request_object`, `login_required`, and the word a request source names). Starts are counted per source (`requests` in `window`).
- Extension points `requestSources` (keyed by name: a start's fields → the JAR, a refusal in its own words, or none; `request`, by value, is its own) and `withoutPasskey` (at most one: whether the screen may offer `create()`, a hint outside T's signature that whoever registers a key judges again; with none, it may not).
- `jarReservations`, the store interface (create unless held, read, change from what it holds), and `jarReservationsNeeds`.
- Contributions: `redirect-uris`' client metadata section to `clients` and its document copy to `client-documents`; the authorization's items but `dpop_jkt` to `approvals`' `statementItems`; its stance.
- To `acr`'s `amrSources`: `authorize.passkey`, amr `pop` and `user`, what a passkey's assertion proves (a key held, the person present); not `hwk`, as no attestation is taken, nor `mfa`, as user verification is the authenticator's own word.
- To `issuer`'s metadata: `authorization_endpoint` (the screen's URL), `response_types_supported` (`code`), `response_modes_supported` (`form_post`), `code_challenge_methods_supported` (`S256`), `require_signed_request_object`, `request_parameter_supported`, `authorization_response_iss_parameter_supported`.
- Operator section: `screen-url` (https), `jar-max-lifetime` (default 10 minutes), `requests` and `window` (default 30 a minute per source), `clock-skew` (default 30 seconds), `delegation-lifetime` (default 1 day: a session's end, from its statement's issue).
- `./testing`: `authorizeConfig` (`AuthorizeSettings`), and `jarReservationsContract`, the store interface's contract test.

## Invariants
- A login is started only by a JAR its client signed (`typ` `oauth-authz-req+jwt`, under `client-assertion`'s algorithms, clock skew and longest lifetime), its `iss` and `client_id` the client, its `aud` this issuer, with a `jti` and an `exp` not past and at most `jar-max-lifetime` away; exactly one request source answers each start.
- A JAR starts one login (A20, internal module `jar`): the same JAR with the same screen keys is answered the same T, made by one call at a time; with other keys, or another JAR under its `jti`, it is refused. Its reservation outlives the JAR's expiry by the clock skew, the margin between replicas' clocks.
- Boot is refused where an item every T carries is filled by no module (`dpop_jkt` with no `approval-binding`), or two modules answer a person with no passkey.
- A JAR asking `openid` where `code-grant` makes no ID token is refused before T is made (`invalid_scope`), and one whose `claims` is malformed or asked without `openid` (`invalid_request_object`, internal module `claims`); so is one whose client may not use the code grant, whose challenge is not S256's shape, or whose `dpop_jkt` is out of its form, so nothing a code needs fails once the person tapped.
- `prompt` is no item of T: `none` is `login_required`, as every login asks the person's passkey; `login`, `consent` and `select_account` are met by that tap and dropped; any other word is refused. A JAR claim no item names is refused.
- The redirect URI is one the client registered, by `redirect-uris`' rule, before anything is reserved or signed.

## Data
- Each JAR's reservation, by its client and `jti`: the digest of the start that used it and the answer made, until the JAR's expiry and the clock skew.

## Depends on
- `kernel`, `http` (the routes), `clients` and `client-documents` (the client, its section), `client-assertion` (`verifySignedBy`), `client-allowance`, `redirect-uris`, `approvals`, `code-grant`, `oidc` (the `claims` parameter's reading), `claims-selection`, `session`, `tokens` (the policies), `sender-binding` (the binding asked for ahead), `acr` (`amrSources`, the acr a passkey's login meets), `issuer`, `rate-limit`, `promises` (its stance), `sdk-core-wire`; `zod`.

## Vocabulary
- start: ②, a login's first request from the screen. JAR: the client's signed request (RFC 9101). reservation: a JAR's one use. source: where a start's JAR comes from.
