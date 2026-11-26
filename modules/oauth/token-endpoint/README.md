# token-endpoint

## Responsibilities
- Answers the token endpoint: authenticates the client, then dispatches to a grant by its grant type; for a request naming no client, has the grant identify it, where the grant can.
- Owns the shape of OAuth error responses (its internal module `answers`).
- Owns each request's issuance bundle (its internal module `bundle`): a grant's `issue` records the bundle's start, then its tokens once, on its subject's flow (the client's own for a client's token), before any is signed, and answers a token only once the bundle is taken in as its owner's `took`.

## Not here
- What a grant is given, and how its answer is answered (`grants`).
- What a client may be issued, and its client metadata section (`client-allowance`). Each grant, the client credentials grant included (`client-credentials`).
- Frames, leases, appending, judgments and abandonment records (`transparency`).

## Offers
- Route `POST /oauth/token`: a form, JSON or no body (any other `415`); cross-origin requests from the operator's origins (`http`) may send `content-type` and `dpop`, and read `dpop-nonce`, `www-authenticate` and `retry-after`.
- Provides `grants`' `composedGrants` (the grant types it dispatches to) and `targets`.
- Where the token endpoint is (`tokenEndpointLocation`): its absolute URL on the origin `issuer` names its endpoints on (`endpointOrigin`), the public origin wherever one is written.
- `oauthError`, `errorDescription`, `authenticateClient` and `refusedAuthenticationAnswer`, for other OAuth endpoints too, as its internal module `answers` says.
- For tests (`./testing`): `grantCaller` (a module providing `grantCalls`) calls a contributed grant as the endpoint does once the client is in, the grant allowed and the binding read, beside `client-allowance`, refusing a mistyped parameter and asking the rule's `untargeted` first; `grantInput` is what it hands the grant.
- `issuer`'s metadata items: `token_endpoint`, `grant_types_supported`, `token_endpoint_auth_methods_supported` and `token_endpoint_auth_signing_alg_values_supported` (left out when `clients` names none).
- Audit events once the client is authenticated, with `client`, `source` (when determined) and `grant_type` (when dispatched to): `token.issued`, and `token.issued.failure` with `reason` and `error` (the code answered); declared in `./audit-events`, listed in the audit event reference.
- Its kind of operation, `token-endpoint.bundle`, in `transparency`'s `operationKinds`; its stances in `promises`' `stances` on `core-compromise-contained`, `no-client-subject-token` and `front-compromise-client-token`, as `built-in`'s card says.
- What `token.issued` adds, the failure's `reason` and a request naming no client's record: `route`'s card; a grant allowed and served by none: `allowed`'s.
- Operator section: `requests` per source in each window (1–100000, default 60) and `window` (1s–1d, default `1m`, written with its unit).

## Invariants
- Boot is refused with no grant composed, so `grant_types_supported` is never empty: left out, a client would read it as `authorization_code` and `implicit` (RFC 8414 §2). A grant composed but allowed to no registered client opens no issuance.
- An issued answer leaves `scope` out when a grant gives it empty, for every grant alike, the test caller too.
- Requests are limited per source by `rate-limit`'s policy before any client is authenticated; over it, `429`.
- A request naming no client goes to a grant that identifies its client only when `clients` refuses it as `no_credentials`, finds it `bare`, and its one `grant_type` names a grant with `identify`; any other refusal is answered as `authenticateClient` answers it. The grant's refusal to identify is its answer; a client identified that is not registered with no credentials (public, method `none`) is `503`. Past that, it is checked as an authenticated client.
- Checking order: client authentication (or, naming no client, the checks to the body, then the grant's `identify`), repeated parameters, mistyped parameters, `grant_type`, the body the grant takes, the client's allowance, the binding, the client's binding requirement, the rule's `untargeted` for a grant without `targets`, the grant, the issuance fences.
- Once a grant has built its answer, before any of it goes out, its one subject issued through `issue` passes `tokens`' fences (`issuanceFencing`): refused, it is a refused issuance (`invalid_grant`, `tokens`' description); unavailable, `503`, losing a refresh token the grant rotated (only where a fence writes, as `subject-revocation` says, and its store does not answer). An answer under no subject or two is the grant's fault, `500`. None of the bundle is answered but passed.
- A repeated parameter is `invalid_request` unless the rule's `repeated` answers it, as is an OAuth parameter sent in JSON as neither a string nor `null` (as if left out); `assertion` is its grant's to define.
- A body the grant does not take is `invalid_request`; a request with no body is read as a form.
- A grant `client-allowance` does not allow the client is `unauthorized_client`.
- The binding is read through `sender-binding`: its refusal is answered with its own code and headers, unavailable as `503`, and two bindings are `invalid_request`. A client that must bind and shows none is `invalid_request`, and one bound by a kind it does not name `unauthorized_client`.
- A grant's `429` carries its wait as `retry-after`, in whole seconds, at least one.
- A bundle whose subject's kind is not the one its grant declares (`subjectKind`) is the grant's fault, `500`, nothing issued.
- Unavailable is the route's declared `503` `temporarily_unavailable`, never audited, warned by `http` as `http.unavailable` with the route, what was unavailable and only a grant type dispatched to.
- No token or secret is ever audited or logged.
- A bundle refused or lost at its append signs nothing; one whose replica falls is never taken over, but abandoned (`bundle`).
- Boot is refused, naming the grant type, when a composed grant declares neither `readsAmbient` `none` nor `cookie`: the token route has no own-site policy and relies on that declaration.

## Depends on
- `kernel`, `http`, `request-source`, `grants`, `clients`, `client-allowance`, `issuer`, `tokens`, `sender-binding`, `rate-limit`, `audit`, `transparency`, `transparency-wire`, `authority-rules` (a client's op id), `promises`
