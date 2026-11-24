# token-introspection

## Responsibilities
- Answers the introspection endpoint (RFC 7662) for access tokens.
- Declares where it stands on the promises a compromised Front must not break.

## Not here
- The token format and its checks: `tokens`.
- Which audiences a client may see: `client-allowance`'s `maySee`.
- Client authentication and the shape of OAuth error answers: `clients`, through `token-endpoint`'s `authenticateClient` and `oauthError`.
- Revocation: `token-revocation`.
- Refusing a deployment that requires those promises: `promises`, by its stances.

## Offers
- Route `POST /oauth/introspect`, answering no other origin.
- `issuer` metadata: `introspection_endpoint`, absolute on the origin `issuer` names its endpoints on (`endpointOrigin`); `introspection_endpoint_auth_methods_supported` (`clients`' methods but `none`) and `introspection_endpoint_auth_signing_alg_values_supported` where a method signs.
- Two stances (`promises`' `stances`), both breaking: `front-compromise-new-authorization` and `front-compromise-client-token`.
- Audit event `introspection.unavailable` (`source` when `request-source` determines it): declared in `./audit-events`.
- Operator section: `requests` (per source and window; 1–100000, default 60) and `window` (written with its unit, `1s` to `1d` in whole seconds, default `1m`).
- It opts in: a composition names it to compose it.

## Invariants
- The route counts requests per source, before any client is authenticated, and answers `429` past the limit.
- The client is authenticated through `token-endpoint`'s `authenticateClient`, handed the audit, which records a refusal as `client.authentication.failure`.
- A public client is refused `401` `invalid_client`; a repeated parameter or a missing `token` is `invalid_request`.
- Active only for a token `tokens` verifies whose audience the caller may see; every other token is `active:false`, whatever its hint.
- An active answer tells `iss`, `sub`, the subject's kind its token carries (`o3co_subject_kind`), `client_id`, `aud`, `scope` where there is one, `exp` and `token_type`, and `cnf` for a bound token; never the token.
- An introspection answer is bound to neither the token asked about nor the request: a resource server trusting it trusts the Front that relays it, so it stands breaking both promises; a deployment requiring either is refused boot by `promises`.
- An unavailable dependency answers `503` `temporarily_unavailable`, never `active:false`, and records `introspection.unavailable`; `http` then warns `http.unavailable` with what and the route.

## Depends on
- `kernel`, `http`, `request-source`, `clients`, `client-allowance`, `issuer`, `tokens`, `token-endpoint`, `rate-limit`, `audit`, `promises`
