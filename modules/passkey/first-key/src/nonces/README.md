# nonces

Internal module of `first-key`: the nonces of a first key's stages.

## Responsibilities
- Issues each stage's nonce for the nonce's lifetime, and uses it once: bound, in one write, to the first request's digest.

## Not here
- What a stage does with a nonce used again: its own. The sealed request's digest: the stage that opens it.

## Offers
- `noncesOf` (the build) → `noncesOver` over `firstKeyNonces` and `nonce-lifetime`. `noncesTakes`: what it takes, which the path names among its takes.
- `noncesOver` (the nonces' store, random bytes, the lifetime) → `issue` (stage) → a nonce; `use` (nonce, stage, digest) → `first`, `again` (the same request), or `refused`.
- Its store, the package's: `firstKeyNonces` (`Kept`: create unless held, read, change from what it holds, never moving the lifetime), and its needs `firstKeyNoncesNeeds`: never evicted, durable, replicated, confirmed reads, authenticated. The nonces name no subject.

## Invariants
- A nonce is 32 random bytes, base64url; a drawn one already held is drawn again, never shared.
- A nonce is used by one request alone: the first to use it binds its digest; the same digest again is `again`, another `refused`, as are an unknown nonce, one of another stage and one past its life.
- Its record names no subject: a stage and a digest.
