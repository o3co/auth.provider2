# publishing

Internal module of `keys`: the rings' public keys, written to files for the publisher to serve.

## Responsibilities
- Writes the authority's set (the JWKS) and the Core's set (what the login screen pins) into the directory `keys-publish` is given.

## Not here
- Serving the files, caching them and when a next key is published before it signs: the publisher and the operator.
- Reading or rotating the keys (`rings`).

## Offers
- `keySets` (the rings, the time → each file's set), `coreJwks` (the rings, a generation → its public keys) and `publish` (the rings, the time, the arguments → the lines and the code `keys-publish` answers).

## Invariants
- `jwks.json` holds the authority's unexpired keys at the time it runs: the signing key, the previous keys and the next, each its public members with its `kid`, its `alg` and `use` `sig`. A key that expires later leaves it only when it is written again.
- `core-keys.json` holds every Core generation's key, in the order of their generations, each as `jwks.json` holds a key with its `generation`, then the sealing key's public members with its `kid` and `use` `enc`.
- No private member is written. Each file is written beside its name and renamed, so a reader never sees half a set.
- Given other than one directory, it writes nothing and answers a usage line and 64.
- It writes into the directory given, adding no path: for an issuer with a path, the operator gives `<dir>/<path>`, as `jwks_uri` names the set under the issuer's URL, while `discovery-publish` adds the path itself; given `<dir>` alone, `jwks_uri` answers 404. `core-keys.json` lands beside it.

## Depends on
- None (`keys`' contract)
