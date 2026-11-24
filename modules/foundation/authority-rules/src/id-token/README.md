# id-token

Internal module of `authority-rules`: an ID token's rules the Core and the monitor derive alike.

## Responsibilities
- Derives an ID token's `c_hash` from the code's digest a record names (A21), so the Core writing it and the monitor checking it give one value.

## Not here
- Putting the claim in the ID token, and which algorithm signs it: `oidc` and `keys`. The code's digest: `code-grant`.

## Offers
- `cHash` (a code's SHA-256 digest, base64url) → the left half, base64url.

## Invariants
- It holds for an ID token signed by an algorithm of SHA-256 alone: the digest is SHA-256, and no other hash's half is made from it.
- A digest that is not 32 bytes in unpadded base64url, its last character carrying no bit past them, is a TypeError.

## Depends on
- Nothing of the package's.
