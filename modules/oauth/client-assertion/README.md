# client-assertion

## Responsibilities
- Contributes `private_key_jwt` (RFC 7523) to `clients`: the client signs a JWT with one of its keys, used once; the method declares `keyHeld`, under asymmetric algorithms alone.
- Contributes the client metadata section that holds the client's keys, its internal module `keys`.
- Decides, for the modules that ask, which key a client's assertion was verified with and whether a JWT is signed by one of its keys.

## Not here
- Client records, lookup, and choosing among methods: `clients`. OAuth error responses: `token-endpoint`.
- Checking the header, key, signature, times, issuer, audience and subject: `external-jwt`, under the policy below.
- Fetching a key set, and how long it is kept: `external-jwt`, through `outbound`.

## Offers
- Composition definition: the method, which names the asymmetric algorithms it takes.
- The client metadata section `client-assertion` (`clientKeys`): `keys`, public RSA, EC or OKP keys as JWKs, default empty; any other key is refused at boot; each is read as internal module `keys`' card says.
  - Or `jwks-uri`, a registered client's alone (a source's client naming one has no key): where the client publishes its key set, an https URL (http only where `outbound` allows plain http), as `url-setting` takes it; never beside written keys. A registered client's `jwks-uri` that `outbound`'s policy refuses refuses boot, with the keys to set (`outbound.refusals`).
  - `accept-loose-audience` (default false): also takes the client's assertions for a loose audience, below. A lasting setting, set by client for one whose library names the token endpoint.
- `clientAssertion`: `verifiedOf` (an authentication's `proof`, its client) → the key its assertion was verified with (`VerifiedKey`: the client, the JWK as its source holds it, its JWK SHA-256 thumbprint, the client's registry version where it has one, and `written` for a key written in its record, never one at its `jwks-uri`); none for anything this module did not make, or another client's.
  - `verifySignedBy` (a client, a JWT, a `typ`) → its claims, or why not: signed by one of the client's keys, written or, a registered client's, at its `jwks-uri`, under `algorithms`, `clock-skew` and `max-lifetime`, its `typ` the one asked; unavailable while the key set cannot be had. Every other claim is the caller's.
- Store interface for spent assertions, `spentAssertions`: save a name for a lifetime, answering `created` or `exists`. Requirements (`spentAssertionsNeeds`): no eviction, survives a crash, never rolled back by failover.
- Operator section: `max-lifetime` (`1s` to `1d` in whole seconds, default `1h`) and `clock-skew` (`0s` to `5m`, default `30s`), each written with its unit; `algorithms` (asymmetric ones `external-jwt` knows; default FAPI 2.0's ES256, PS256 and EdDSA, for an assertion and a request object alike; any other only where named). Naming RS256, RS384 or RS512 warns `client-assertion.pkcs1v15_deprecated` at every start, in `keys`' words.
- `./testing`: `clientAssertionConfig`, the section for test clients (`clientKeysFor`), and the store interface's contract test (`spentAssertionsContract`).

## Invariants
- The three values are read from the body only, a form or a JSON object; never from the query.
- A request carrying `client_assertion` or `client_assertion_type`, sent, given twice or in JSON not as a string, is this method's alone (RFC 7521 §4.2.1). The method says it authenticates by an assertion, so a refusal for malformed credentials, or for another method beside it, of a request it claims is marked as the assertion's (`clients`); its finding a request with no assertion malformed marks nothing.
- Only one of the two, an empty `client_assertion`, or either part or `client_id` given twice or, in JSON, not as a string is malformed credentials, before anything is judged or spent. An assertion type other than `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` is refused, never left to another method.
- `client_id`, when given, names the client; otherwise the assertion's `iss` does. `iss` and `sub` are the client's id.
- `aud` is `issuer`'s URL as one string, judged before the `jti` is spent: the token endpoint's URL, or a list, could be for another authorization server that names this one's token endpoint.
- A client whose section sets `accept-loose-audience` is also taken with a loose audience: the token endpoint's absolute URL from `token-endpoint`, or a list holding either URL. Each is logged as a `client-assertion.loose_audience` warning with the client, and each registered client that sets it as a `client-assertion.accept_loose_audience` warning with the client at every start.
- Without `http`'s public origin, boot is refused, whether or not a client accepts a loose audience, though `token-endpoint` names its location on the issuer's origin without one; and without that location.
- The assertion is checked against the client's own keys, written or, a registered client's, at its `jwks-uri`, in the operator's `algorithms`; the method names them. Which algorithm each key is read under, and the warning of one read under none, are `keys`' card's. A key set is fetched from its URL's host alone; while it cannot be fetched, the answer is unavailable.
- The longest lifetime is `max-lifetime`; the clock allowance is `clock-skew`. `jti` is a well-formed string of 1–256 characters, a fixed bound as it becomes a store key (clients send UUID-like values).
- A spent `jti` is kept per client, past the assertion's end by five minutes, the widest `clock-skew` a section takes, whatever is set, and a minute for the store's clock: a `clock-skew` widened later on the same store never takes it again.
- The `jti` is spent last, after every other check. A spent `jti` is refused. One the store cannot answer for is unavailable. A refusal tells the caller nothing more; its reason is logged.

## Data
- Spent assertions, named by a hash of the client id and the `jti` together, so no two clients' names meet.

## Depends on
- `kernel`, `http`, `url-setting`, `clients`, `issuer`, `token-endpoint`, `external-jwt`, `keys`, `outbound`, `outbound-policy`

## Vocabulary
- assertion: a JWT the client signed with its own key to prove itself. spent assertion: an assertion whose `jti` was used, kept so it cannot be used again. loose audience: an assertion's `aud` that is not `issuer`'s URL as one string, but names it or the token endpoint.
