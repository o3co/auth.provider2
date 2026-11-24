# keys

Internal module of `client-assertion`: the client metadata section that holds a client's keys for its assertions, and whether it is taken with a loose audience.

## Responsibilities
- Reads a client's keys, written in or a key set's URL, and where they come from; checks at boot that `outbound` lets a registered client's key set URL through.
- Reads whether the client accepts a loose audience (`accept-loose-audience`, default false).

## Not here
- Checking an assertion, its audience among it, and spending it (the package). Fetching the key set (`external-jwt`, through `outbound`).

## Offers
- `clientKeys`, the section; `keysOf` (the section) → where the keys come from; `clientKeysIn` (the build context) → the section with its boot check, `outbound`'s refusals taken from the composition.
- `unreadKeys` (the section, the algorithms taken) → the places (`keys.<n>`) of the written keys none of them reads.

## Invariants
- A written key is a public RSA, EC or OKP key for verifying signatures, read by `keys`' rules; written keys and a key set's URL are never both given.
- A key set is fetched from its URL's host alone.
- Each key is read under one algorithm (`external-jwt`): a key naming no `alg` where two are taken for its kind (RS256 and PS256), or naming one not taken, is read under none. Written for a registered client, it is warned of at every start (next); in a key set at a `jwks-uri`, or for a client whose metadata is fetched when it asks (`clients-cimd`), it is found only at the request, as no key.
- Each written key of a registered client read under none is logged at every start as a `client-assertion.key_unread` warning, with the client and the key's place (`keys.<n>`), never its value. Deprecated: a later release refuses boot for such a key. Give it an `alg` among `algorithms`, or take only one for its kind.

## Depends on
- `clients` (the section's form), `external-jwt` (a key source), `keys`, `url-setting`, `outbound-policy` (the boot check), `kernel` (the build context)
