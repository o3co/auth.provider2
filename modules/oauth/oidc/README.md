# oidc

## Responsibilities
- Makes a redemption's ID token, a part of its bundle (a contribution to `code-grant`'s `idTokens`, for the `openid` scope), signed by the authority's ring (internal module `id-token`).
- Holds the fixed claim table and maps a subject's attributes through it, and reads the `claims` request parameter for `authorize-claims` (internal module `claims`).

## Not here
- When an ID token is asked, and the code's facts (`code-grant`, from `authorize` and `approvals`). Recording the bundle (`token-endpoint`). Signing, the rings and their algorithms (`keys`). `c_hash` from the code's digest (`authority-rules`).
- What a subject's attributes hold and where they come from (`subject-attributes`). Which names a client and the approval allow, and the pin (`claims-selection`).
- Whether the `claims` parameter is read, and its metadata item `claims_parameter_supported` (`authorize-claims`, which reads it).
- An ID token given back as a hint, a client's choice of algorithm (`id_token_signed_response_alg`) and the refresh response (which returns no ID token): none here. Accepting a token for userinfo (`userinfo`).

## Offers
- `claimsAsked` (a `claims` parameter, a JSON object → the `sub` values each member asks and the selection; or `malformed`); `scopeOfClaim`, `tableScopes`, `tableClaims`; the type `Claim`; `idTokenTyp` (`JWT`).
- Contract `releasedClaims`: `of` (subject, scope words, the session's handle, what a request asked beyond its scope → the claims released by the ID token's own rule; never `sub`), the one way userinfo reads claims.
- A contribution to `code-grant`'s `idTokens`; to `claims-selection`'s `claimScopes` (each table claim's scope, none outside the table).
- `issuer`'s metadata items: `scopes_supported` (`openid` and the table's), `claims_supported` (`sub` and the table's), `subject_types_supported` (`public`), `id_token_signing_alg_values_supported` (the authority's ring's algorithm, as `keys` names it).
- Its stance: `core-compromise-contained` does not hold, as an ID token carries no receipt of the log yet (`txr`, with `tokens`' at L1).
- Operator section: `id-token-lifetime` (`1m`–`1d`, written with a unit; default `1h`).

## Invariants
- An ID token is signed by the authority's ring's algorithm, which `keys` chooses and warns of; `oidc` names none of its own.
- Held for now (A21): boot is refused unless the authority's ring signs by an algorithm of SHA-256 (ES256, RS256, PS256), with "set the authority's ring to an algorithm of SHA-256"; a next key of another warns at each boot (`oidc.next_key_alg_refused`).
  - Why: `c_hash` is the left half of the ID token's algorithm's hash, and the log names a code by its SHA-256 alone, from which the monitor checks it.
  - Lifted once the log's code digest is of each algorithm's hash: a wire change, the owner's to decide.
- The claims of an ID token, the table's release and the `claims` parameter's reading: `id-token`'s and `claims`' cards.

## Claim table
| scope | claim | attribute | type |
|---|---|---|---|
| `profile` | `name`, `picture` | the same name | string |
| `email` | `email` | `email` | string |
| `email` | `email_verified` | `email_verified` | boolean |
| `groups` | `groups` | `groups` | list of strings |

## Depends on
- `kernel`, `keys`, `issuer`, `code-grant`, `claims-selection`, `subject-attributes`, `promises`; the internal modules' own.

## Vocabulary
- claim table: the fixed rows of scope, claim, attribute and type.
- released claims: a subject's attributes mapped through the table for the scopes and names asked.
