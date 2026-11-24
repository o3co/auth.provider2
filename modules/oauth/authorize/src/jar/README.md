# jar

Internal module of `authorize`: a login's JAR, from its source to its one use.

## Responsibilities
- Reads the JAR from the one source that answers, verifies it as its client's, and reserves its one use (A20).

## Not here
- The route, the redirect URI, `prompt` and the items (`start`).

## Offers
- `jarOf` (`JarParts`, the fields, the client) → the JAR (bytes, claims, `jti`, `exp`) or a refusal. `reserving` (the store, skew, clock) → the run of one reserved start. `startDigest` (JAR, `eEnc`, `eSig`). `sha256`.

## Invariants
- A start with no source answering, or more than one, is refused; a source's refusal is `invalid_request_uri`.
- A JAR past its `exp` is refused; its reservation lives the clock skew longer.
- A reservation is keyed by the digest of client and `jti`, holds the digest of the JAR's bytes and the screen's keys, the call making its answer (held 30 seconds) and the answer once kept. A start whose digest is another's is refused; one whose answer is kept is given it again; one with none kept makes it where no live call holds it, and is told to ask again (`temporarily_unavailable`) where one does. A making that is refused lets go at once.
- A record of another shape is a store that cannot tell: unavailable.

## Depends on
- `client-assertion` (`verifySignedBy`), `sdk-core-wire` (`typs`, the canonical text).
