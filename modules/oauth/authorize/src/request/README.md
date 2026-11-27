# request

Internal module of `authorize`: a login's request checked after its JAR is verified, for the start and for a module taking a JAR elsewhere (`par`).

## Responsibilities
- Checks a verified JAR's request for its client, in order: the redirect URI it registered, `prompt`, T's items from the JAR, an OpenID request where no ID token is made, its `claims`, what its code needs; it answers T's items or the refusal.

## Not here
- The JAR's source, envelope and reservation (`jar`). What a code needs, and the resource's reading by its rule (`code-needs`). T's length against its route, the screen's keys, `withoutPasskey` and the sign-up offer: the start's alone.

## Offers
- `requestsOver` (`RequestParts`: what a code needs, the `claims` reader and its `hint`) → `AuthorizationRequests` (`checked`); `itemsRefusal` (the wire's spelling → the refusal); `itemMaxBytes`; `requestsIn` and `requestsTakes` over the composition, which `authorize` provides as `authorizationRequests`; `claimsUnread` (the reader where none is contributed).

## Invariants
- The redirect URI is one the client registered, by `redirect-uris`' rule; else `invalid_request`.
- `prompt` is no item of T: `none` is `login_required`, as every login asks the person's passkey; `login`, `consent` and `select_account` are met by that tap and dropped; any other word is `invalid_request`.
- Under PAR, T's `request_uri` is the one the start gives; a push gives none.
- `checked` is the check, then the JAR's `id_token_hint` verified by `requestClaims`' `hint` (OIDC Core §3.1.2.2: an ID token of this issuer, for the client) for the subject T holds as read (`hint_sub`), so no forged payload's `sub` reaches T: one call, nothing to forget. One refused, or any where no module reads hints, is `invalid_request`, in the reader's words.
- `display`, `ui_locales`, `claims_locales`, `login_hint`, `max_age` and `acr_values` are taken and dropped (`sdk-core-wire`'s `jarClaims.ignored`): no item of T, read by nothing in the Core. `max_age` is met by every login, a fresh tap whose `auth_time` the ID token always carries; a value that is no whole number of seconds is `invalid_request` (`item:max_age`). A Front cannot add one: the JAR is the RP's, signed, and `jar_hash` binds its bytes.
- T's items refused by `sdk-core-wire` are read by its spelling, one rule (RFC 9101 §6.3, `itemsRefusal`): `missing_item:` and `item:` are a parameter's fault, `invalid_request` (PKCE, `state`, `nonce`, `scope`, `response_mode`, `response_type`, `dpop_jkt`, `max_age`, `id_token_hint`); `unknown_item:` (a claim outside the set, a `request_uri` in the JAR among them), `item:claims`, and any spelling not known are the request object's, `invalid_request_object`. The spelling is the description.
- `state` and `nonce` are each at most 512 bytes, counted in UTF-8 (`itemMaxBytes`), else `invalid_request`: this project's bound, as RFC 6749 sets none. It keeps T room within its route beside a long client, redirect URI, scope and `claims`, but does not make T fit: `fits` is the start's.
- After T's items and their bound: an OpenID request where no ID token is made, the `claims` read (`requestClaims`, any refused where no module reads them), then what a code needs (`code-needs`' `atStart`).
- A need unmet is `unauthorized_client` (the code grant, RFC 6749 §4.1.2.1), `invalid_request` (the challenge's form, the binding's), `invalid_target` (the resource, RFC 8707 §2, with the rule's description; so T never shows a resource its token would not carry), `invalid_scope` (an OpenID request where no ID token is made, a scope outside the client's allowance, RFC 9126 §2.1).
- A JAR's `claims` asking a claim by `null` (an ID token's or userinfo's request) goes into T as `{}`; one that is no JSON object (§5.5's own form), or holding any other null, is `invalid_request_object` (`item:claims`, `sdk-core-wire`'s), before T. The null rule alone is a deviation, where §5.5 has a member not understood ignored: T is signed whole and its signer writes no null.
- Boot is refused where two modules read a request's claims, or two rules read the audience asked.

## Depends on
- `redirect-uris` (`redirects`, `matches`), `sdk-core-wire` (`itemsFromJar`), `issuer` (its URL, for what a code needs), `kernel`; the package's `code-needs`, `jar` (`sha256`, `Verified`) and contract (`requestClaims`, `AuthorizationRequests`).
