# jar

Internal module of `authorize`: a login's JAR, from its source to its one use.

## Responsibilities
- Reads the JAR from the one source that answers, verifies it as its client's, and reserves its one use (A20).

## Not here
- The route (`start`). The request's check: the redirect URI, `prompt`, the items (`request`).

## Offers
- `jarVerified` (`JarVerifying`, the client, a JAR's bytes) → its claims, `jti` and `exp`, or why it is refused; the package's contract offers it.
- `jarOf` (`JarParts`, the fields, the client) → the JAR (bytes, claims, `jti`, `exp`) or a refusal, `jarVerified`'s as `invalid_request_object`. `reserving` (the store, skew, clock) → the run of one reserved start. `startDigest` (JAR, `eEnc`, `eSig`). `sha256`.

## Invariants
- A start with no source answering, or more than one, is refused; a source's refusal is answered in the source's own words (`par`'s is `invalid_request_uri`).
- A JAR past its `exp`, or with its `exp` more than `jar-max-lifetime` away, is refused, as is one with no `nbf`, an `nbf` more than 60 minutes past, or an `exp` more than 60 minutes from its `nbf` (FAPI 2.0 Message Signing §5.3.1); an `nbf` ahead is the signature check's, under the clock skew. Each envelope check refuses in words of its own. Its reservation outlives the JAR's expiry by the clock skew, the margin between replicas' clocks.
- A reservation is keyed by the digest of client and `jti`, holds the digest of the JAR's bytes and the screen's keys, the call making its answer (held 30 seconds) and the answer once kept. A start whose digest is another's is refused; one whose answer is kept is given it again; one with none kept makes it where no live call holds it, and is told to ask again (`temporarily_unavailable`) where one does. A making that is refused lets go at once.
- A record of another shape is a store that cannot tell: unavailable.

## Depends on
- `client-assertion` (`verifySignedBy`), `sdk-core-wire` (`typs`, the canonical text).
