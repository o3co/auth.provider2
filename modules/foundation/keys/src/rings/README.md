# rings

Internal module of `keys`: the two rings, read at boot from the section and the holder, and signing and verifying with them.

## Responsibilities
- Reads the operator's authority ring (`signing`, `next`, `previous`), the Core's ring (`generation` and a key for each) and the sealing key into the rings at boot, from what the holder holds by each kid, refusing any key not held, not of its `alg`'s kind, or one that must sign and cannot.
- Prepares a ring's header under a `typ`, signs a payload under it through the holder, and verifies a token by the ring's key its `kid` names, or by a Core generation's key alone.
- Verifies a compact JWS at once over JWKs given, for a caller that holds the keys (authority-rules' checks).

## Not here
- Holding keys and signing bytes: the holder. Publishing the public keys (`publishing`). Sealing (`sealing`). Outside parties' keys (`material`).

## Offers
- `section` (the operator section, each `kid` unique across it), `rs256Named`, `readRings` (the section and the holder → the rings, the Core's by generation, or the refusals by key path), `ringSigner` (a ring → its `prepare`, `sign` and `verify`), `verifiedBy`, `jwkOf`, `jsonOf`, `refusingAccessTokens`, and the ring's `kinds`, `underAlg`, `expired`, `pointOf` and `publicHalf`.

## Invariants
- The JWS header is `alg`, `typ` and `kid`, written as prepared; the payload is the caller's bytes as given, and the signature the holder's bytes as a JWS writes them. A signer signs only under a prepared value it gave.
- A prepared value says how many bytes the signing key's signature takes: an RSA key's modulus, two coordinates of its curve for ES256, 64 for Ed25519 (114 for Ed448), so a caller knows a token's size before it is signed; for a key of another kind, `prepare` is a TypeError, never a length guessed.
- JSON (a payload, a header) is read by transparency-wire's `tokens.parse`: a member named twice reads as none.
- The authority's next key verifies and is published but never signs; a previous key verifies until its `expires-at`.
- The Core's ring holds one key for each generation, the current one among them; the ring verifies by the current one, and a generation's key by itself.
- One key serves one ring, one generation or the sealing: a key held for a second kid refuses boot, by its public half.
- EdDSA takes Ed25519, ES256 P-256, PS256 and RS256 RSA of 2048 bits or more. The signature is as RFC 7518 §3 writes it: ECDSA's r and s, PSS's salt as long as SHA-256.
- RS256 is deprecated, not refused, for `material`'s one reason (`pkcs1v15Deprecated`). Each start names the `alg` paths of the ring keys under it in one warning, `keys.rs256_deprecated`, saying it. ES256 is recommended.
- `verifiedBy` takes the key its `kid` names among those given, read as an outside JWK (`material`), of the kind the header's `alg` names, its own `alg` the same where it has one.
- A key's public half is taken whatever the holder answers.

## Depends on
- None (`keys`' contract)
