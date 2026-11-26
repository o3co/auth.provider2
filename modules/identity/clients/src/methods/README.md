# methods

Internal module of `clients`: the built-in authentication methods, `client_secret_basic`, `client_secret_post` and `none`, and the section holding a secret's hash.

## Responsibilities
- Reads a request's credentials for each built-in method, and checks a secret against the client's hash through `secret-hash`.
- Owns the built-in section `client-secret` (`hash`) and which methods need it.

## Not here
- Choosing among the methods composed, the order of refusals and the timing of an unknown client: the internal module `registry`. Hashing and its work: `secret-hash`.

## Offers
- `secretBasic`, `secretPost` (a `SecretChecker`) → an `AuthMethod`; `none`, an `AuthMethod`.
- `secretSection`; `secretMethods`, the methods whose clients must hold a hash; `hashesOf` (the registered records) → their hashes, for the checker's decoys; `sends` (a request, a name) → whether its body sends it.

## Invariants
- A Basic header is malformed unless it is canonical base64 of UTF-8 that decodes to a non-empty id and secret; a `client_id` in the body beside it must name the same client, or the credentials are bad.
- A `client_secret` is malformed unless one non-empty `client_id` is sent once beside it; a `client_id` alone is malformed when sent twice or not as a string, and no credentials when empty.
- `client_secret_post` and `none` read `client_id` and `client_secret` from a form or JSON body, where a value that is not a string still counts as sent.
- A secret is checked through `secret-hash`, within its assembly's `max-concurrent`, with decoys of the registered hashes' work; boot refuses a registered `hash` it cannot read (plain text included) or a secret method's client with none. A source's client of a secret method is refused as an invalid record before any secret is checked (the internal module `registry`).

## Depends on
- `http` (the request), `secret-hash` (reading and checking a hash), `zod`; the package's contract.
