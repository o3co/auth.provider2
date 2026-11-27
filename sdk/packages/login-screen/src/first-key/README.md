# first-key

Internal module of `login-screen`: the first key's path on the screen (O11; the account first), and a creation's next steps any path takes.

## Responsibilities
- Starts the first key, sends the mail side, recovers a lost creation's answer, and runs a creation's `create()`, continuation and possession, for this path and for the creations `management` and `signUp` read.

## Offers
- `firstKey`:
  - `start` (the identifier and a password if asked, the start's nonce, the Core's sealing key, the screen keys): the request sealed to the Core. `openCode` (the sealed answer, the nonce): the start's code. Each, or why not.
  - `mail` (the token from the link's fragment, the identifier, the code, the mail side's nonce): a `Mail`: the sealed request, its nonce, the evidence's value (the token's hash) and the ciphertext's hash; or why not.
  - `recover` (a `Mail`), where the creation's answer was lost: the nonce, the digest (the ciphertext's hash) and E_sig's signature over `firstKey.recoverInput`, with the keys the mail was sealed under; or why not (a `Mail` this page did not seal). A reloaded page has lost its mails, and recovers none.
  - `readCreation` (the creation, the `Mail`): a `ReadCreation` of the first key's path (no `basis`, or `first-key`), its evidence and ciphertext hash the screen's own, or why not.
  - `createOptions` (a `ReadCreation`, the RP's name): what `create()` is asked: the create challenge, the creation's subject and RP, the account named by the creation's `user_name` where it gives one (F1), else its masked `account`, a resident key of the algorithms the creation offers in its order, user verification; or why not.
  - `continuation` (a `ReadCreation`, the sequence, the response's text, the screen keys the creation names): the register stage's signature, ES256's raw r||s, base64url; or why not (a sequence under 1 among them: its upper bound is the Front's and the Core's).
  - `readPossession` (the possession, the `ReadCreation`, the credential's id, SPKI and COSE algorithm from `create()`: `getPublicKey()` as it gives it, `getPublicKeyAlgorithm()`): a `ReadPossession`, naming this creation, the screen's own new key and credential, or why not. `assertionOptions` (a `ReadPossession`): the new key's `get()`, for its credential alone, at the RP the creation named.

## Invariants
- A new key is of an algorithm the creation offered (COSE ES256, EdDSA or RS256), its SPKI read as a key of that algorithm in its one DER form, and named by its JWK thumbprint (`key_jkt`) by passkey-key-wire's `passkeyThumbprintInput`, the vectors both sides share passing the same way. A browser whose WebCrypto lacks an algorithm the creation offers (Ed25519 in an older one) refuses a key of it as `key`, after `create()`: the deployment offers what its screens' browsers read.
- A creation's ciphertext hash is the SHA-256 of the sealed mail request's whole: its `enc` (65 bytes) then its `ct`.

## Depends on
- `sdk-core-wire`, `continuation-wire`, `passkey-key-wire`.
- The package's `statement`, `challenge`, `hpke`, `jws`, `keys` and `bytes`.
