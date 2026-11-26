# par

## Responsibilities
- Takes a client's pushed authorization request (RFC 9126): authenticates the client, verifies its JAR, takes a DPoP proof only of the key the JAR names (A44), and keeps the JAR under a fresh `request_uri`.
- Answers a login's start that names a `request_uri`, as a source of `authorize`'s requests. Owns the pushed requests' store interface and its needs.

## Not here
- The login's start, its JAR's one use (A20) and T: `authorize` and `approvals`, which verify the JAR again where the login starts. The client's authentication: `clients`. A JWT's signature: `client-assertion`. A DPoP proof and its key: `sender-binding`'s kinds (`dpop`).

## Offers
- `POST /oauth/par` (`front-core-wire`'s `par`: a form of the client's authentication and `request`, a `DPoP` header where sent) → `201` `{ request_uri, expires_in }`; or an OAuth error: `invalid_client` (`401`), `invalid_request`, `invalid_request_object`, `invalid_dpop_proof` and a binding kind's own words with its headers (`use_dpop_nonce` with `DPoP-Nonce`) (`400`), `rate_limited` (`429`). Pushes are counted per source (`requests` in `window`).
- A contribution to `authorize`'s `requestSources` (`request_uri`: a start's `requestUri` → the JAR pushed under it, for the client that pushed it; `invalid_request_uri` for any other).
- A contribution to `issuer`'s metadata: `pushed_authorization_request_endpoint`.
- `pushedRequests`, the store interface (create unless held, read), and `pushedRequestsNeeds`.
- Operator section: `jar-max-lifetime` (default 90 seconds; at most `authorize`'s, or a JAR pushed is refused where its login starts), `requests` and `window` (default 60 a minute per source), `clock-skew` (default 30 seconds).
- `./testing`: `parConfig` (`ParSettings`), and `pushedRequestsContract`, the store interface's contract test.

## Invariants
- A push carries no parameter twice (RFC 6749 §3.1, §3.2): one sent twice is `invalid_request` ("repeated parameter"), read before any other and before the client's authentication, so none passes as if left out. Through a Front, a name the wire's `par` does not carry is dropped there, never reaching the Core.
- A push carries its JAR alone (no parameter but inside it): one sending `request_uri` or `authorization_details` is refused (RFC 9126 §2.1), and a `client_id` beside the authentication must be the client's.
- The JAR is taken by `authorize`'s check (`jarVerified`) with `jar-max-lifetime`: the authenticated client's (`iss` and `client_id`), for this issuer, with a `jti` and an `exp` not past and at most `jar-max-lifetime` away; it names a `dpop_jkt` too.
- The header-only way of asking a DPoP binding (RFC 9449 §10.1) is not taken: the JAR names the key, a push with no proof is taken (its tokens are bound to the JAR's key), and a proof of the binding it asks is taken only where it is of that key; its expiry is checked again after the proof.
- A `request_uri` is 256 random bits under `urn:ietf:params:oauth:request_uri:`; its record lives the JAR's life and the clock skew. Many pushes of one JAR meet at the one start `authorize` reserves by client and `jti`, so each JAR starts one login however often it is pushed.

## Data
- Each pushed request, by its `request_uri`: the client and the JAR's bytes, until the JAR's expiry and the clock skew.

## Depends on
- `kernel`, `http` (the route), `rate-limit` (its policy), `clients` (`authenticate`), `client-assertion` (`verifySignedBy`, given to `jarVerified`), `sender-binding` (the binding proved and asked), `issuer` (its URL, metadata), `authorize` (`requestSources`, `jarVerified`); `zod`.

## Vocabulary
- push: a pushed authorization request. `request_uri`: the name a push is kept under, which a login's start names.
