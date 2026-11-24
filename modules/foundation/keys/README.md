# keys

## Responsibilities
- Owns the provider's two rings and what their keys mean: the authority's, whose keys sign the tokens it issues and whose public keys are the JWKS, and the Core's, a key for each Core generation, whose keys sign the statements and the completion's answer and whose public keys the login screen pins.
- Signs and verifies with them, seals to a screen's key and opens what a screen sealed, through the keys axis's one adapter, which holds the keys.
- Writes both rings' public keys to files for the publisher to serve: an expired key leaves `jwks.json` only when it is written again, so the publisher writes it again at each `expires-at`.
- Reads public key material from outside (PEM and JWK) by one set of rules, for every module that verifies another party's signature, and the settings that hold a secret's bytes.

## Not here
- Holding the keys and the operations on them: the adapter of the keys axis (`./holder`). Serving the files: the publisher.
- The meaning of what is signed and sealed, and the info and suite words of a sealing: the caller's, and sdk-core-wire's. Which outside keys a module trusts.

## Offers
- `keys`: `prepare(ring, typ)`, the header (`alg`, `typ`, `kid`) fixed before signing, its text and the signature's length (`rings`' card); `sign(prepared, bytes)` (a JSON object's bytes signed as given under it) answering the JWS or `withdrawn`; `algorithm(ring)` and `nextAlgorithm(ring)`.
- `keys`' verifications, each valid with frozen claims or why not (`malformed`, `typ`, `kid_unknown`, `kid_expired`, `signature`): `verify(ring, token, typ)`, and `verifyOf(generation, token, typ)` by the Core generation named; `generation()`, the one this Core signs as; `coreRing(generation)`, its public keys; `verifyJws(jws, keys)`, at once over the JWKs given (authority-rules' `Checks.verifyJws`).
- `keys` also: `seal` and `open` (internal module `sealing`), `powers` (whether the holder's signing can be withdrawn outside the Core, and its calls counted outside the Core's account), and `publish`, the app entry `keys-publish <directory>` (internal module `publishing`).
- `Ring` (`authority` or `core`), `Header`, `Prepared`, `Signed`, `Read`, `Sealed`, `Opened`, `Powers`, `Published`; for adapters, `KeyHolder`, `Held`, `SignAnswer`, `AgreeAnswer`.
- `accessTokenSigning`: `prepare()` and `sign(prepared, bytes)` an access token (`at+jwt`) on the authority's ring, and `verify(token)`: the one way to either, as `keys` refuses its type, taken by the module `tokens` alone (any other taking it refuses boot) and imported by `tokens` alone, as the manifest's `takenBy` declares.
- `./holder`, kept for the adapters its `takenBy` names: `keyHolders`, the one holder (exactly one: none, or two, refuses boot, saying to compose one adapter of the keys axis).
- Outside material (internal module `material`): `publicJwk`, `publicPem` (`withForm`), `thumbprint`, `verifiesUnder`, `verifyAlgorithms` (`VerifyAlgorithm`), `isVerifyAlgorithm`, `publicMembers`, `isCanonicalJws`, `Jwk`, `PemForm`; secret settings (internal module `secret`): `secretBytes` (exactly or at least n) and `bearerToken` (at least n).
- Operator section (internal module `rings`): `authority` (`signing`, `next`, `previous` with `expires-at`), `core` (`generation`, `keys`, one for each generation) and `sealing`, each a `kid` and the signing ones an `alg`.
- `./testing`: `keysConfig` (the section with ES256 keys in both rings and a sealing key) and `testHolder` (a module holding those keys and any given, in process).

## Invariants
- `keys` and `accessTokenSigning` are taken only by a module that declares where it stands on the promises (the kernel's `takersContribute`, with `promises`' `stances`); one declaring nothing refuses boot.
- `sign` writes the prepared header byte for byte (`headerText`), with the kid prepared; a prepared value that signer did not give is the caller's TypeError. So a digest of the header and the claims taken before signing is the signed token's.
- A ring signs with one key: the authority's `signing`, and the Core's key of its `generation`. The authority's next key is published and verifies, but never signs; a Core generation's key verifies only where `verifyOf` names it, or the current one.
- A token is verified by the ring's key its `kid` names, after its `typ`, and refused once that key's `expires-at` is reached; a ring verifies by its own keys alone.
- `prepare` and the verifications refuse the access token type (`at+jwt` in any case, `application/` and media type parameters too) as the caller's TypeError; `sign` refuses a payload that is no JSON object, or names a member twice at any depth (transparency-wire's `tokens.parse`), too.
- Claims holding a null, at any depth, are never signed: the refusal, and the error `keys.null_claims` logged with it, name their key paths, never their values.
- A payload the key signed that is no JSON is answered as a bad signature; a compact JWS not in its one form, as malformed.
- A `withdrawn` answer is apart from a failure, and logged (`keys.withdrawn`, with what it was for and the kid); an outage is the holder's to throw.
- A `kid` is 1–128 of letters, digits and `. _ ~ -`, unique across the section, as the holder holds keys by kid.
- A key the holder does not hold, one not of its `alg`'s kind, a signing key the holder cannot sign with under its `alg`, a sealing key that is no P-256 key the holder agrees with, and one key held for two kids (across the rings, the generations and the sealing), refuse boot at its kid's path (each `alg`'s kind: `rings`' card); a ring key under RS256, deprecated, boots, warned of at every start (`keys.rs256_deprecated`).
- Only a key's public half is used to verify and to publish, whatever the holder answers.
- An outside JWK with a private member, a `kid` that is no string, or a key member not in its one form, is refused; so is a private PEM. An outside key may verify only for signatures (`use`, `key_ops`) and only under an algorithm its kind and curve fit.

## Depends on
- `kernel`, `promises`, `sdk-core-wire`, `transparency-wire`

## Vocabulary
- ring: the keys of one use, the one that signs now and those that verify.
- holder: the adapter that holds the keys and does the operations on them, reading none of what they mean.
- claim / `typ`: the content and type of a JWT being signed, owned by the side that asks for the signature.
