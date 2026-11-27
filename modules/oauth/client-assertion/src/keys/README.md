# keys

Internal module of `client-assertion`: the client metadata section that holds a client's keys for its assertions, and whether it is taken with a loose audience.

## Responsibilities
- Reads a client's keys, written in or a key set's URL, and where they come from; checks at boot that `outbound` lets a registered client's key set URL through.
- Reads whether the client accepts a loose audience (`accept-loose-audience`, default false).
- Says where the registered clients' sections leave claim 2: the package's stance.

## Not here
- Checking an assertion, its audience among it, and spending it (internal module `method`). Fetching the key set (`external-jwt`, through `outbound`).

## Offers
- `clientKeys`, the section; `keysOf` (the section) → where the keys come from; `keysFor` (a client) → the keys its assertions and JWTs are checked against, none for a source's client naming a `jwks-uri`; `clientKeysIn` (the build context) → the section with its boot check, `outbound`'s refusals taken from the composition.
- `keysStance` (the registered clients) → the package's `Stance` on claim 2. `looseFor` (a client) → whether its assertion is also taken for a loose audience: a registered client's choice alone (§0.2).
- `unreadKeys` (the section, the algorithms taken) → the places (`keys.<n>`) of the written keys none of them reads.
- The section's fields beside `keys`:
  - `jwks-uri`, a registered client's alone (a source's client naming one has no key): where the client publishes its key set, an https URL (http only where `outbound` allows plain http), as `url-setting` takes it; never beside written keys. A registered client's `jwks-uri` that `outbound`'s policy refuses refuses boot, with the keys to set (`outbound.refusals`).
  - `accept-loose-audience` (default false): also takes the client's assertions for a loose audience (the package's card). A lasting setting, set by client for one whose library names the token endpoint.

## Invariants
- A written key is a public RSA, EC or OKP (Ed25519, never Ed448) key for verifying signatures, read by `keys`' rules for outside keys: no private member, a `kid` that is a string, `use` `sig` and `key_ops` holding `verify` where given. Written keys and a key set's URL are never both given.
- A key set is fetched from its URL's host alone, and only for a registered client: a source's client takes its written keys alone (R8, §3.11), one naming a `jwks-uri` having no key, and nothing is fetched for it.
- Each key is read under one algorithm (`external-jwt`): a key naming no `alg` where two are taken for its kind (RS256 and PS256), or naming one not taken, is read under none. Written for a registered client, it is warned of at every start (next); in a key set at a `jwks-uri`, or for a client whose metadata is fetched when it asks (`clients-cimd`), it is found only at the request, as no key.
- Each schema-valid written key of a registered client read under none (an Ed448 key fails the schema first) is logged at every start as a `client-assertion.key_unread` warning, with the client and the key's place (`keys.<n>`), never its value. Deprecated: a later release refuses boot for such a key. Give it an `alg` among `algorithms`, or take only one for its kind.
- Claim 2 is broken by a registered client naming a `jwks-uri` (its key set is whoever serves it, or over plain http sits on its path), or taking a loose audience (an assertion made for another server taken here); the first such, either field, is named by its place and field, `clients.registered.<i>.sections.client-assertion.<field>`, never by its id. Held otherwise. A source's client weakens nothing: it takes written keys alone, and never a loose audience.
- A `jwks-uri` costs more than claim 2: a JWT naming a `kid` the kept set lacks has the set fetched again (`external-jwt`, at most once a minute), one naming a `kid` it holds does not, so the time to answer tells them apart to anyone sending one before it is authenticated, though the words do not. Its keys are public.

## Depends on
- `clients` (the section's form), `external-jwt` (a key source), `keys`, `url-setting`, `outbound-policy` (the boot check), `promises` (the stance's words), `kernel` (the build context)
