# login-screen

## Responsibilities
- The login screen's SDK: what the screen runs between the person and the Core, following the screen–Core protocol (`sdk-core-wire`) and the transparency log's (`transparency-wire`).

## Not here
- Sending and receiving: the caller fetches each operation (`front-core-wire`'s names and routes), hands the SDK what it read and sends what the SDK gives. Reading a refusal's body (front-core-wire's `refusals`, by its status and `error`): the page.
- The ciphertext hash's input as a protocol function, the `create()` response's form (so one `create()` result yields both the continuation's response and the possession's credential, which today the caller keeps together), and reading a new key from `authData`'s COSE where `getPublicKey()` gives none: they land with the protocol packages' change (V22).
- Whether ②'s answer lets F1 (sign-up, the credential first) start, and the passkey's name in `user_name`: the provider's; the screen takes the creation as it comes.
- A bundle that fixes no log keys (L0) for an authorization's `finish`: no way here yet (a key change's has, `keyChanges.read`'s `L0`); it comes as an explicit choice, never as a missing key list.
- The relying party's checks: `rp-kit`.

## Offers
- `screenKeys()`: a ceremony's fresh screen keys, E_enc (an HPKE P-256 point, `eEnc`) and E_sig (a P-256 signing key, `eSig`, as a statement carries it), their private halves not exportable (`ScreenKeys`).
- `answers.read` (a form, the success's body as the page parsed it): the SDK's value by sdk-core-wire's `payloads.answers` (`authorization` → T and `create`, its challenge left for the screen to compute; `statement` → the compact JWS; `sealed` → `Sealed`, bytes; `nonce`); none for another shape or a form it does not know. A literal form reads to that form's value, `overHttp`'s text to any form's. Whether `enc` is a point is the opening's to see.
- `readStatement` (compact, purpose, the Core ring's public keys, the screen keys, the issuer): the statement as its purpose's schema reads it, or why not (`StatementError`).
- `challengeOf` (statement, `get` or `create`): the WebAuthn challenge's bytes.
- `authorization`: an authorization's steps on the screen.
  - `read` (T, the JAR the screen holds, the ring, the screen keys, the issuer): T as a `ReadT` (the statement and its compact bytes), its items exactly what the JAR gives by sdk-core-wire's rule, or why not (`AuthorizationError`). Only `read` makes a `ReadT`; the next steps refuse any other.
  - `assertionOptions` (a `ReadT`, the RP id, the credentials if any): what a passkey's `get()` is asked: T's get challenge, user verification required; credentials given empty, or any one not a credential id, are refused.
  - `finish` (a `ReadT`, sealed, ⑤'s receipt, the completion's additional data, the screen keys, the ring, the log's keys, the issuer, the assertion's bytes): the code and ⑤'s record (shard, n), or why not (`FinishError`). `Sealed`: an encapsulated key and a ciphertext.
  - `callbackProof` (a `ReadT`, the `Finished` that `finish` gave for it, the screen keys T names, the time): the callback's proof (A38) the screen adds to its POST to the RP, ES256 under E_sig, its header carrying E_sig's key; or why not, a `Finished` not given for this T among them.
- `management`: the keys' management (V22: `passkey-add`, `passkey-manage`).
  - `read` (the statement, the purpose asked for, the ring, the screen keys, the issuer) → a `ReadManage`, or a statement's refusal (another purpose's is `payload`).
  - `finish` (a `ReadManage`, sealed, the ring, the screen keys, the issuer, the assertion's bytes): the approval's completion under `completionAad` of its purpose: passkey-manage's keys' list (a rename's `continued` refused), or passkey-add's creation as a `ReadCreation` (its `basis` passkey-add, its evidence the statement's hash) that `firstKey`'s next steps take; or why not (`ManagementFinishError`).
  - `continuation` (a passkey-manage `ReadManage`, `delete` or `rename`, the sequence 1 to 16, the body, the screen keys and the Core's sealing key) → the sealed value (V24): the body and its E_sig signature over the plaintext body's hash, padded to one length and bound to stage, statement and sequence, and what was sent (`Continued`); or why not. A resend sends the same sealed value, kept by the caller.
  - `renamed` (a rename's `Continued`, the sealed answer, as `finish` takes): the new keys' list, its `continued` naming exactly the rename sent (sequence, body's hash); or why not (a `Continued` that is no rename's among them).
- `signUp`: F1's path on the screen (sign-up, the credential first; §3.13), from a `ReadT`.
  - `continuation` (a `ReadT`, the screen keys T names): what `continue` sends, the stage `sign-up`, sequence 1, the body `{}` and E_sig's signature over continuation-wire's `of` (T's hash, 1, the body's hash); or why not. One per T (sequence 1 alone): a resend, signed again or not, is answered with what the Core kept, the creation or a final refusal (`pending` while the first runs).
  - `readCreation` (the creation, the `ReadT`, the ring, the screen keys T names, the issuer): a `ReadCreation` of `basis` `sign-up`, its evidence T's hash, that `firstKey`'s next steps take (`createOptions`, `continuation`, `readPossession`); its key change's purpose is `sign-up`. Or why not.
  - T is approved after by the registered key: `authorization.assertionOptions` given that credential alone. Where the sign-up stage's refusal is final, or T's approval by a key held before is refused, the screen starts the authorization again.
- `keyChanges.read` (what was waited for: a possession and the new key's assertion, or a delete's `Continued`; the sealed completion; the ring, the screen keys, the issuer; the level the caller names, `L0` or `log` with every log input): the change, exactly the one waited for, under its path's purpose; at `log` also §C.5's four (the receipt, its age, the status, the stateOf, its state read by flow-state-wire holding the key added, not the one deleted). Or a refusal no fetch changes (`KeyChangeError`), or `retry` with the receipt read (`KeyChangeRetry`): the status or stateOf to fetch and give back in the checks.
- `firstKey`: the first key's path on the screen (O11; the account first).
  - `start` (the identifier and a password if asked, the start's nonce, the Core's sealing key, the screen keys): the request sealed to the Core. `openCode` (the sealed answer, the nonce): the start's code. Each, or why not.
  - `mail` (the token from the link's fragment, the identifier, the code, the mail side's nonce): a `Mail`: the sealed request, its nonce, the evidence's value (the token's hash) and the ciphertext's hash; or why not.
  - `recover` (a `Mail`), where the creation's answer was lost: the nonce, the digest (the ciphertext's hash) and E_sig's signature over `firstKey.recoverInput`, with the keys the mail was sealed under; or why not (a `Mail` this page did not seal). A reloaded page has lost its mails, and recovers none.
  - `readCreation` (the creation, the `Mail`): a `ReadCreation` of the first key's path (no `basis`, or `first-key`), its evidence and ciphertext hash the screen's own, or why not.
  - `createOptions` (a `ReadCreation`, the RP's name): what `create()` is asked: the create challenge, the creation's subject and RP, the account named by the creation's `user_name` where it gives one (F1), else its masked `account`, a resident key of the algorithms the creation offers in its order, user verification; or why not.
  - `continuation` (a `ReadCreation`, the sequence, the response's text, the screen keys the creation names): the register stage's signature, ES256's raw r||s, base64url; or why not (a sequence under 1 among them: its upper bound is the Front's and the Core's).
  - `readPossession` (the possession, the `ReadCreation`, the credential's id, SPKI and COSE algorithm from `create()`: `getPublicKey()` as it gives it, `getPublicKeyAlgorithm()`): a `ReadPossession`, naming this creation, the screen's own new key and credential, or why not. `assertionOptions` (a `ReadPossession`): the new key's `get()`, for its credential alone, at the RP the creation named.

## Invariants
- It depends on the provider's protocol packages alone (the sdk's guard).
- Shipped code runs in a browser: WebCrypto, no Node builtins.
- HPKE is the suite `sdk-core-wire` names, base mode, one message per context (sequence 0), as RFC 9180 gives it (its test vector in the tests).
- A JWS verifies with a key under that key's own algorithm alone (ES256, EdDSA, RS256, PS256), which the header must name; a key with no `alg` is taken by its curve (EC P-256, Ed25519), never an RSA key, which fits two. A key with a private member, a public member missing or not canonical, a `use` not `sig`, `key_ops` without `verify`, or an RSA modulus under 2048 bits verifies nothing. A header with `crit` or `b64` is refused: no extension is implemented. Base64url is read in its one canonical spelling.
- A statement is read before it is shown: it must name the screen's own E_enc and E_sig, so a Front that swapped them is refused. Its times, as a completion's, are the Core's to hold at acceptance.
- A completion is never read under T's `typ`, nor a statement under the completion's, and is taken only with ⑤'s receipt (A35): signed by the log, an `approval` record's, binding the digests of the T approved, the assertion sent and the code.
- The JAR is read without its signature, which the Core verifies; the screen compares its items alone.
- No key of the log's, nor of a status's or stateOf's signer set, may be one of the Core ring's, keys told apart by their kind's public members alone: a Core holding both would sign its own proof.
- A key change is shown taken only once every check its level names passed. A refusal the log's objects gave (denied, the record's result, the state) stays with the change, and a status or stateOf older than one read before for it is not taken, so no older object, no source made again, nor a read of the same change beside it, undoes what was read, for as long as the page lives (a reload forgets it, with the sources).
- A credential list is never dropped to none: an empty or unreadable one is refused, not widened to any credential.
- Hashes are SHA-256, base64url without padding. A creation's ciphertext hash is the SHA-256 of the sealed mail request's whole: its `enc` (65 bytes) then its `ct`.
- Each step takes only what the step before made (`ReadT`, `Mail`, `ReadCreation`, `ReadPossession`, `ReadManage`, `Continued`): a copy, or one made elsewhere, is refused. What a step hands on is frozen, its bytes aside.
- A new key is of an algorithm the creation offered (COSE ES256, EdDSA or RS256), its SPKI read as a key of that algorithm in its one DER form, and named by its JWK thumbprint (`key_jkt`) by passkey-key-wire's `passkeyThumbprintInput`, the vectors both sides share passing the same way. A browser whose WebCrypto lacks an algorithm the creation offers (Ed25519 in an older one) refuses a key of it as `key`, after `create()`: the deployment offers what its screens' browsers read.

## Depends on
- `sdk-core-wire` (the words, the payloads, the items' rule, the inputs), `continuation-wire` (a continuation's stages, bodies and bytes), `passkey-key-wire` (a passkey's key form and its vectors), `transparency-wire` (the receipt, the status, the stateOf, their signer sets), `flow-state-wire` (a stateOf's state, read).
- `front-core-wire`, for a test alone: the answer forms and purposes it names agree with sdk-core-wire's, the stages with continuation-wire's.
