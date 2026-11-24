# claims

Internal module of `oidc`: the claim table, mapping a user's attributes through it, and reading the `claims` request parameter.

## Responsibilities
- Holds the fixed claim table: which claims each scope releases, and the attribute (by `users`' name) and type each is read from.
- Maps attributes to claims through the table, for scope words and for table claims asked by name, and leaves out a released claim its constraint does not hold.
- Reads a `claims` parameter (OpenID Connect Core §5.5) into the `sub` values and the `acr` it asks, and the table claims it names with their constraints.

## Not here
- Where the attributes come from (`subject-attributes`, through `oidc`'s module). Which names a client and the approval allow (`claims-selection`).

## Offers
- `claimsOf` (attributes, scope words, optionally a target asked → the released claims, frozen); `scopeOfClaim`, `tableScopes`, `tableClaims`; the type `Claim`.
- `claimsAsked` (the parameter, a JSON object → the `sub` values and the `acr` each member asks, kept apart, and the selection; or `malformed`).

## Invariants
- Only the table's claims are released; an attribute outside it, a value of another type, or a nested object never is. From `groups`, elements that are not strings are dropped.
- A scope word counts only when it is exactly a table scope. A claim asked by name is released only when it is a table claim.
- A released claim that a constraint asked of the same target does not hold is left out, whether its scope or its name released it (Core §5.5.1): the value must equal the constraint's value or one of its values, type and all; a list claim any constraint names is left out.
- A parameter or an `id_token` or `userinfo` member that is not an object, a `sub`, `acr` or table claim of no shape §5.5.1 gives (`null`, or `essential` a boolean, `value`, or a non-empty `values`, not both), or a table claim past the bounds `claims-selection` keeps, is malformed. Any other member or claim (`auth_time` among them, which an ID token always carries) is passed over.

## Depends on
- `claims-selection` (the selection's types and bounds), `users` (the attribute names).
