# login-screen

## Responsibilities
- The login screen's SDK: what the screen runs between the person and the Core, following the screen–Core protocol (`sdk-core-wire`) and the transparency log's (`transparency-wire`).

## Not here
- What crosses the network, as the protocol's review settled it (V22) and the protocol packages do not yet hold: each operation's request, route and name (`loginStart`, `loginFinish`, `firstKeyNonce`, `firstKeyStart`, `firstKeyMail`, `firstKeyRecover`, `approvalStart`, `approvalFinish`, `continue`, `keyFinish`: `front-core-wire`'s), and each answer's form (`statement`, `sealed`, `nonce`), the sealed value's `{ enc, ct }`, the completion's additional data (`completionAad`) and ⑤'s receipt carried in the login's completion (`sdk-core-wire`'s). Until they land, the caller hands the SDK the statement, the sealed value, the additional data and the receipt it read, and sends what the SDK gives.
- The ciphertext hash's input as a protocol function, the `create()` response's form (so one `create()` result yields both the continuation's response and the possession's credential, which today the caller keeps together), and reading a new key from `authData`'s COSE where `getPublicKey()` gives none: they land with the protocol packages' change (V22).
- F1 (sign-up: the credential first), whose creation names the T the screen read as its evidence and no ciphertext: sdk-core-wire holds its form (`basis` `sign-up`, no `ct_hash`); the screen's path is not written yet.
- The management screen beyond `passkey-manage`'s statement and its sealed continuation (`passkey-add`, the keys' list, §C.3's checks), the first key's recovery (`firstKeyRecover`), a key change's completion (its receipt, status and `stateOf`): they land with the screen's own stage.
- A bundle that fixes no log keys (L0): it has no way here yet; V22 lets it take a completion without the receipt, and that comes as an explicit choice with the protocol packages' change, never as a missing key list.
- The relying party's checks: `rp-kit`.

## Offers
- `screenKeys()`: a ceremony's fresh screen keys, E_enc (an HPKE P-256 point, `eEnc`) and E_sig (a P-256 signing key, `eSig`, as a statement carries it), their private halves not exportable (`ScreenKeys`).
- `readStatement` (compact, purpose, the Core ring's public keys, the screen keys, the issuer): the statement as its purpose's schema reads it, or why not (`signature`, `typ`, `payload`, `keys`, `issuer`).
- `challengeOf` (statement, `get` or `create`): the WebAuthn challenge's bytes.
- `authorization`: an authorization's steps on the screen.
  - `read` (T, the JAR the screen holds, the ring, the screen keys, the issuer): T as a `ReadT` (the statement and its compact bytes), its items exactly what the JAR gives by sdk-core-wire's rule, or why not (a statement's refusal, `jar`, `items`). Only `read` makes a `ReadT`; the next steps refuse any other (`statement`).
  - `assertionOptions` (a `ReadT`, the RP id, the credentials if any): what a passkey's `get()` is asked: T's get challenge, user verification required; credentials given empty, or any one not a credential id, are refused (`credentials`).
  - `finish` (a `ReadT`, sealed, ⑤'s receipt, the completion's additional data, the screen keys, the ring, the log's keys, the issuer, the assertion's bytes): the code and ⑤'s record (shard, n), or why not (`statement`, `keys`, `open`, `signature`, `typ`, `payload`, `issuer`, `assertion`, `receipt`). `Sealed`: an encapsulated key and a ciphertext.
  - `callbackProof` (a `ReadT`, the `Finished` that `finish` gave for it, the screen keys T names, the time): the callback's proof (A38) the screen adds to its POST to the RP, ES256 under E_sig, its header carrying E_sig's key; or `statement`, `finish` (not what `finish` gave for this T), `keys`, `proof`.
- `management`: `read` (a `passkey-manage` statement, the ring, the screen keys, the issuer) → a `ReadManage`, or a statement's refusal; `continuation` (a `ReadManage`, `delete` or `rename`, the sequence 1 to 16, the body, the screen keys and the Core's sealing key) → the sealed value (V24): the body and its E_sig signature over the plaintext body's hash, padded to one length and bound to stage, statement and sequence; or `statement`, `keys`, `sequence`, `body`. A resend sends the same sealed value, kept by the caller.
- `firstKey`: the first key's path on the screen (O11; the account first).
  - `start` (the identifier and a password if asked, the start's nonce, the Core's sealing key, the screen keys): the request sealed to the Core, or `plain`. `openCode` (the sealed answer, the nonce): the start's code, or `open`, `payload`.
  - `mail` (the token from the link's fragment, the identifier, the code, the mail side's nonce): a `Mail`: the sealed request, its nonce, the evidence's value (the token's hash) and the ciphertext's hash.
  - `recover` (a `Mail`), where the creation's answer was lost: the nonce, the digest (the ciphertext's hash) and E_sig's signature over `firstKey.recoverInput`, with the keys the mail was sealed under; or `mail`. A reloaded page has lost its mails, and recovers none.
  - `readCreation` (the creation, the `Mail`): a `ReadCreation` of the first key's path (no `basis`, or `first-key`), its evidence and ciphertext hash the screen's own, or why not (a statement's refusal, `mail`, `basis`, `evidence`, `ciphertext`).
  - `createOptions` (a `ReadCreation`, the RP's name): what `create()` is asked: the create challenge, the creation's subject and RP, a resident key of the algorithms the creation offers in its order, user verification; or `statement`, `options`.
  - `continuation` (a `ReadCreation`, the sequence, the response's text, the screen keys the creation names): the register stage's signature, ES256's raw r||s, base64url; or `statement`, `keys`, `sequence` (a sequence under 1; its upper bound is the Front's and the Core's).
  - `readPossession` (the possession, the `ReadCreation`, the credential's id, SPKI and COSE algorithm from `create()`: `getPublicKey()` as it gives it, `getPublicKeyAlgorithm()`): a `ReadPossession`, naming this creation, the screen's own new key and credential, or why not (a statement's refusal, `statement`, `creation`, `key`, `credential`). `assertionOptions` (a `ReadPossession`): the new key's `get()`, for its credential alone, at the RP the creation named.

## Invariants
- It depends on the provider's protocol packages alone (the sdk's guard).
- Shipped code runs in a browser: WebCrypto, no Node builtins.
- HPKE is the suite `sdk-core-wire` names, base mode, one message per context (sequence 0), as RFC 9180 gives it (its test vector in the tests).
- A JWS verifies with a key under that key's own algorithm alone (ES256, EdDSA, RS256, PS256), which the header must name; a key with no `alg` is taken by its curve (EC P-256, Ed25519), never an RSA key, which fits two. A key with a private member, a public member missing or not canonical, a `use` not `sig`, `key_ops` without `verify`, or an RSA modulus under 2048 bits verifies nothing. A header with `crit` or `b64` is refused: no extension is implemented. Base64url is read in its one canonical spelling.
- A statement is read before it is shown: it must name the screen's own E_enc and E_sig, so a Front that swapped them is refused. Its times, as a completion's, are the Core's to hold at acceptance.
- A completion is never read under T's `typ`, nor a statement under the completion's, and is taken only with ⑤'s receipt (A35): signed by the log, an `approval` record's, binding the digests of the T approved, the assertion sent and the code.
- The JAR is read without its signature, which the Core verifies; the screen compares its items alone.
- No key of the log's may be one of the Core ring's, keys told apart by their kind's public members alone: a Core holding both would sign its own receipt.
- A credential list is never dropped to none: an empty or unreadable one is refused, not widened to any credential.
- Hashes are SHA-256, base64url without padding. A creation's ciphertext hash is the SHA-256 of the sealed mail request's whole: its `enc` (65 bytes) then its `ct`.
- Each step takes only what the step before made (`ReadT`, `Mail`, `ReadCreation`, `ReadPossession`): a copy, or one made elsewhere, is refused. What a step hands on is frozen, its bytes aside.
- A new key is of an algorithm the creation offered (COSE ES256, EdDSA or RS256), its SPKI read as a key of that algorithm in its one DER form, and named by its JWK thumbprint (`key_jkt`) by sdk-core-wire's `keyThumbprintInput`, the vectors both sides share passing the same way. A browser whose WebCrypto lacks an algorithm the creation offers (Ed25519 in an older one) refuses a key of it as `key`, after `create()`: the deployment offers what its screens' browsers read.

## Depends on
- `sdk-core-wire` (the words, the payloads, the items' rule, the inputs), `transparency-wire` (the receipt).
