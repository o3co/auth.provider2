# authorize-claims

Bridge between `authorize` and `claims-selection`: comes wherever both are composed.

## Responsibilities
- Reads an OpenID request's `claims` parameter for `authorize` (`requestClaims`): refuses at ②, before T is made, one malformed or asked without `openid`; at the finish selects what it asks, by the client's allowance and what the person agreed to in the approval (O19), and keeps the selection for the code.
- Reads a JAR's `id_token_hint` for `authorize` (`hint`, at the push and the start) by `oidc`'s reader (`idTokenHints`), where `oidc` is composed.
- Says in the metadata that the parameter is supported, where it is read and ID tokens are made.

## Not here
- Where the start and the finish ask, and their answers to each refusal: `authorize`.
- Reading the parameter: `oidc`'s `claimsAsked`; verifying a hint: `oidc`'s `idTokenHints`. The selection's rules, its records and what is kept for the code: `claims-selection`.

## Offers
- `authorize`'s `requestClaims`, the one reading of a request's claims: `refusal` (T's `claims`, whether the request is OpenID's) → why it is refused, or none; `select` (client, subject, the scope's words, T's `claims`, the login's acr) → none asked, `otherSubject`, `acrUnmet`, or `selected` with its `keep` (the code's digest, its lifetime, the subject); `hint` (the hint, the client → its subject, or why none), left out where `oidc`'s reader is not composed.
- `issuer`'s metadata item `claims_parameter_supported`: `true` where `code-grant` makes ID tokens, else left out.

## Invariants
- Opts in as `authorize` does: it comes where `authorize` and `claims-selection` are both composed, never bringing `authorize` alone.
- What the person agreed to is T's own: its scope's words and the names its `claims` asked, read from the statement used, never a later request.
- A `sub` a member asks is the one subject the login may answer for (Core §5.5.1): another is `otherSubject`, for the finish to refuse before a session opens.
- An essential `acr` a member asks (§5.5.1.1) is met by the login's acr alone, one of its values where it names any: else `acrUnmet`, for the finish to refuse as an authentication that failed. One not essential is voluntary.
- A parameter read malformed at the finish, past ②, is a `TypeError`.
- Keeps no record of its own: what is kept for the code is `claims-selection`'s.

## Depends on
- `authorize` (`requestClaims`), `claims-selection`, `code-grant` (`issuesIdTokens`), `issuer` (`metadata`), `oidc` (`claimsAsked`, `idTokenHints`, taken optionally), `kernel`.
