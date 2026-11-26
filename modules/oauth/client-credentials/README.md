# client-credentials

## Responsibilities
- Contributes the client credentials grant (RFC 6749 §4.4): a confidential client of a version its publisher signed takes a token for itself, within its own ceiling, authenticated by a key written in its record and bound to that key by DPoP.
- Counts how often each client is issued, and keeps the clients the operator suspended from it.

## Not here
- Authenticating the client, the endpoint and its answers, the stance its declaration gives on `no-client-subject-token`, and the bundle a token is issued in, recorded on the client's own flow (`token-endpoint`). What a client may be issued for itself (`client-allowance`). Issuing the token (`tokens`, through `grants`' `issue`). Which keys are the client's (`client-assertion`). Counting in windows (`rate-limit`). Reading a DPoP proof (`dpop`, through `sender-binding`).

## Offers
- Contribution to `grants`: `client_credentials` (`clientCredentialsGrantType`), declaring the client's own subject (`subjectKind` `client`) and `keyHold` `assertion`, reading no ambient credential, taking its audience from the request.
- `clientCredentials` (issuer, `client-assertion`'s `verifiedOf`, the limits: a count, the requests a minute, the clients suspended) → the grant, for an assembly of one's own; `dpopMember`, the `cnf` member a DPoP-bound token carries.
- Operator section: `lifetime`, how long its token lives (`1m` to `15m`, `authority-rules`' `tokenRules.client.lifetimeMs`, default `5m`, written with its unit), `requests`, the requests a client may make in a minute (1–100000, default 60), and `suspended`, the clients issued nothing, by id (default none).
- It opts in (`optIn`): `combinations`' full template leaves it out unless something composed needs it; composing it brings `dpop`, which it needs to run.

## Invariants
- Only a confidential client is served; a public one is `unauthorized_client`, and so is a suspended one.
- Each request is counted by the client's id, once the client is authenticated, so no one else can use up its requests: over the limit, `429` with the wait (`rate_limited`); when it cannot count, unavailable, never let through.
- Only a client whose assertion a key written in its record verified is served (`client-assertion`'s `verifiedOf`, `written`, of what its authentication verified, for this client); a secret's, or a key at its `jwks-uri`, is `unauthorized_client`. No setting weakens it.
- The token is bound by DPoP to that very key: its `cnf` is that key's thumbprint, so using it needs the client's private key. A proof by another key is `invalid_dpop_proof`; no binding is `invalid_request`, and one of another kind `unauthorized_client`. Boot is refused where no binding kind composed writes `jkt`.
- The scope and audience are the client's own ceiling's alone (`client-allowance`'s `allowedSelfIssuance`), never its person's delegation: the scope named, the audience asked within its own audiences, never the issuer; a client not of a signed version is issued nothing.
- The audience is asked through `grants`' rule for it: with no rule composed, a ceiling of two entries or more issues nothing, and a `resource` asked that the rule did not read must be the one entry's audience, else `invalid_target`.
- The token's subject and the client it is issued to are both the client, its subject's kind `client`; it lives `lifetime`, never past fifteen minutes; it is one bundle on the client's own flow, naming no root, its start the client's assertion and DPoP proof; no refresh credential is issued. Nothing but the count is used up before issuing.

## Depends on
- `grants`, `client-allowance`, `client-assertion`, `authority-rules` (the fifteen minutes), `issuer` (its URL), `rate-limit` (the count), `sender-binding` (the binding kinds composed), `dpop` (brought, never imported), `kernel`, `zod`
