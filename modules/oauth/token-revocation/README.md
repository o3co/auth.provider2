# token-revocation

## Responsibilities
- Answers the revocation endpoint (RFC 7009).
- Revokes access tokens through `tokens`, and other token kinds through the modules that contribute them.

## Not here
- The token format and its revocation: `tokens`.
- What a contributed token kind does when revoked: the contributing module.
- Client authentication and the shape of OAuth error answers: `clients`, through `token-endpoint`'s `authenticateClient` and `oauthError`.
- Introspection: `token-introspection`.

## Offers
- Route `POST /oauth/revoke`, answering `http`'s listed origins: a page may send `authorization` and `content-type`, and read `www-authenticate` and `retry-after`.
- Extension point `revocableKinds`: revocable token kinds, one per hint; a kind takes a token and a client and answers written, done, unknown or unsupported.
- `issuer` metadata, only where some token can be revoked: `revocation_endpoint`, absolute on the origin `issuer` names its endpoints on (`endpointOrigin`); `revocation_endpoint_auth_methods_supported` (`clients`' methods, `none` included) and `revocation_endpoint_auth_signing_alg_values_supported` where a method signs.
- Audit event `token.revoked` (`client`, `source` when `request-source` determines it, and `token_type`, the kind's hint), never holding a token: declared in `./audit-events`.
- Operator section: `requests` (per source and window; 1–100000, default 60) and `window` (written with its unit, `1s` to `1d` in whole seconds, default `1m`).

## Invariants
- The route counts requests per source, before any client is authenticated, and answers `429` past the limit.
- The client is authenticated through `token-endpoint`'s `authenticateClient`, handed the audit, which records a refusal as `client.authentication.failure`.
- A repeated parameter or a missing `token` is `invalid_request`.
- Only the client a token was issued to can revoke it; another client gets `200` and the token stays.
- An access token's revocation is written on every request, past any earlier one, and answered only once confirmed.
- Access tokens are tried first; the hint only moves its kind ahead, and each kind is tried once at most. A token no kind knows gets `200`.
- A kind that cannot revoke its token gets `unsupported_token_type`, as do access tokens where `tokens` cannot revoke them.
- A contribution for the hint `access_token` refuses boot.
- An unavailable dependency answers `503` `temporarily_unavailable`, never `200`; `http` then warns `http.unavailable` with what and the route.

## Depends on
- `kernel`, `http`, `request-source`, `clients`, `issuer`, `tokens`, `token-endpoint`, `rate-limit`, `audit`

## Vocabulary
- written: this request wrote the token's revocation.
- done: nothing is left to do, as for a token already revoked or issued to another client.
