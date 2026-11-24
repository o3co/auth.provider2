# claims

Internal module of `authorize`: an OpenID request's `claims` parameter, read at ② and selected at the finish.

## Responsibilities
- Refuses at ②, before T is made, a `claims` parameter that is malformed or asked without `openid`.
- At the finish, selects what the parameter asks, by the client's allowance and what the person agreed to in the approval (O19), and pins the selection to the code.

## Not here
- Reading the parameter (`oidc`'s `claimsAsked`). The selection's rules, its records and the pin (`claims-selection`). Where in the finish this runs (`finish`).

## Offers
- `claimsRefusal` (T's `claims`, whether the request is OpenID's) → why it is refused, or none.
- `claimsPinning` (`claims-selection`'s `select` and `keepForCode`) → `ClaimsPinning`: `select` (client, subject, the scope's words, T's `claims`, the login's acr) → none asked, the selection, `otherSubject` or `acrUnmet`; `keep`, the selection kept for the code. `claimsPinningIn`, `claimsTakes`: the same over the composition.

## Invariants
- What the person agreed to is T's own: its scope's words and the names its `claims` asked, read from the statement used, never a later request.
- A `sub` a member asks is the one subject the login may answer for (Core §5.5.1): another is `otherSubject`, for the finish to refuse before a session opens.
- An essential `acr` a member asks (§5.5.1.1) is met by the login's acr alone, one of its values where it names any: else `acrUnmet`, for the finish to refuse as an authentication that failed. One not essential is voluntary.
- A parameter read malformed at the finish, past ②, is a `TypeError`.

## Depends on
- `oidc` (`claimsAsked`), `claims-selection`, `clients` (the client's type), `kernel`.
