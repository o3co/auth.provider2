# material

Internal module of `keys`: reading public key material from outside, by one set of rules.

## Responsibilities
- Reads a public key written as PEM or as a JWK, rebuilds a JWK from its public members, tells whether a JWK may verify under an algorithm, answers a key's thumbprint, and tells whether a compact JWS is written in its one form.

## Not here
- The provider's own keys and signing (`rings`). Which outside keys a module trusts (the module's).

## Offers
- `publicJwk`, `publicPem` (asked `withForm`, with the form it was written in: a public key, or a certificate its key is taken out of, nothing of the certificate checked), `publicMembers`, `verifiesUnder` (which reads `isVerifyAlgorithm`, offered to this module's tests alone), `verifyAlgorithms`, `pkcs1v15Deprecated` (why RS256, RS384 and RS512 are deprecated, in one text), `thumbprint`, `isCanonicalJws` and `canonical` (whether a base64url text is its bytes' one form).

## Invariants
- A key member is taken only in the one base64url form its bytes encode, so one key has one JWK.
- A private member, a `kid` that is no string, or a private PEM is refused before the platform reads the key.
- The platform reads the key (`createPublicKey`); jose is used here only for the thumbprint; it stays inside `keys`.
- A key fits an algorithm by its kind and curve: EdDSA by Ed25519 alone (FAPI 2.0 §5.4.1), never Ed448; ES256 by P-256, ES384 by P-384, ES512 by P-521; RS* and PS* by RSA.

## Depends on
- None (`keys`' contract)
