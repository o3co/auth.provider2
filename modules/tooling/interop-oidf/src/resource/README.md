# resource

Internal module of `interop-oidf`: the resource the OIDF run calls with its access tokens, for its tests alone.

## Responsibilities
- Plays the resource server the suite calls, as nextgen offers none: it takes the provider's DPoP-bound access token with a DPoP proof of the key the token is bound to, behind an https front (`conformance-front`) at its own origin, and answers the token's subject and scope.
- Keeps each refusal it answered, in its words.

## Not here
- The provider's checks of tokens and proofs: its modules'. A run's result here speaks of the token and its binding the provider issued, and of these checks, never of a provider's resource.
- The provider: `scene`. The login that ends with a token: `screen` (`signedIn`).

## Offers
- `startResource` (the host and the address to listen on, a directory, the issuer, the audience and the authority's published keys, each read at every call) → `Resource`: its URL, the certificate its front answers with, what it refused, its stop. `thumbprintOf` (RFC 7638, EC, RSA and OKP).

## Invariants
- It answers at `/resource` alone. A JWS (token or proof) is three base64url segments, its `alg` a string, no `crit`; it is taken under PS256 (RSA of 2048 bits or more), ES256 (P-256) or EdDSA (Ed25519) alone (FAPI 2.0 §5.4.1).
- The token (RFC 9068 §4): `typ` `at+jwt`; by the published key its `kid` names; of the issuer; for the audience (the issuer, where no `resource` is asked, as its test pins); not expired, nor before its `nbf`; bound by `cnf.jkt`; sent as `DPoP` (the scheme in any case) in `Authorization` alone.
- The proof (RFC 9449 §4.3): one `DPoP` header; `typ` `dpop+jwt`; a public `jwk` it is signed by; `htm` the call's method; `htu` the call's URL without query or fragment, scheme and host in any case, the default port resolved; `iat` within 60 s either way; `ath` the token's hash; a `jti` taken once, spent only by a call taken.
- A call with no credentials is `401` with the challenge alone (RFC 6750 §3.1); a token in the query `400` `invalid_request`; a token failing a check, or a proof of another key, `401` `invalid_token`; a proof failing one, `401` `invalid_dpop_proof` (RFC 9449 §7.1). Each `401` names `algs`.
- A call's `x-fapi-interaction-id` is echoed; Node writes its `Date` header.
- Its files are tests' (`test/`).

## Depends on
- `conformance-front`, `lifecycle` (`stopAll`); its tests: `screen` (`signedIn`), `rp` (`dpopKey`, `thumbprint`), `scene` (`ask`).
