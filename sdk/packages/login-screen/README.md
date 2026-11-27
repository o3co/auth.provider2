# login-screen

## Responsibilities
- The login screen's SDK: what the screen runs between the person and the Core, following the screen–Core protocol (`sdk-core-wire`) and the transparency log's (`transparency-wire`).

## Not here
- Sending and receiving: the caller fetches each operation (`front-core-wire`'s names and routes), hands the SDK what it read and sends what the SDK gives. Reading a refusal's body (front-core-wire's `refusals`, by its status and `error`): the page.
- The ciphertext hash's input as a protocol function, the `create()` response's form (so one `create()` result yields both the continuation's response and the possession's credential, which today the caller keeps together), and reading a new key from `authData`'s COSE where `getPublicKey()` gives none: they land with the protocol packages' change (V22).
- Whether ②'s answer lets F1 (sign-up, the credential first) start, and the passkey's name in `user_name`: the provider's; the screen takes the creation as it comes.
- The relying party's checks: `rp-kit`.

## Offers
- `screenKeys()`: a ceremony's fresh screen keys, E_enc (an HPKE P-256 point, `eEnc`) and E_sig (a P-256 signing key, `eSig`, as a statement carries it), their private halves not exportable (`ScreenKeys`).
- `answers.read` (a form, the success's body as the page parsed it): the SDK's value by sdk-core-wire's `payloads.answers` (`authorization` → T and `create`, its challenge left for the screen to compute; `statement` → the compact JWS; `sealed` → `Sealed`, bytes; `nonce`); none for another shape or a form it does not know. A literal form reads to that form's value, `overHttp`'s text to any form's. Whether `enc` is a point is the opening's to see.
- `readStatement` (compact, purpose, the Core ring's public keys, the screen keys, the issuer): the statement as its purpose's schema reads it, or why not (`StatementError`).
- `challengeOf` (statement, `get` or `create`): the WebAuthn challenge's bytes.
- `authorization`: an authorization's steps on the screen (internal module `authorization`).
- `management`: the keys' management (V22: `passkey-add`, `passkey-manage`; internal module `management`).
- `signUp`: F1's path on the screen (sign-up, the credential first; internal module `sign-up`).
- `keyChanges.read`: a key change's completion, read and shown taken (internal module `key-changes`).
- `firstKey`: the first key's path on the screen (O11), and a creation's next steps (internal module `first-key`).

## Invariants
- It depends on the provider's protocol packages alone (the sdk's guard).
- Shipped code runs in a browser: WebCrypto, no Node builtins.
- HPKE is the suite `sdk-core-wire` names, base mode, one message per context (sequence 0), as RFC 9180 gives it (its test vector in the tests).
- A JWS verifies with a key under that key's own algorithm alone (ES256, EdDSA, RS256, PS256), which the header must name; a key with no `alg` is taken by its curve (EC P-256, Ed25519), never an RSA key, which fits two.
- A key with a private member, a public member missing or not canonical, a `use` not `sig`, `key_ops` without `verify`, or an RSA modulus under 2048 bits verifies nothing. A header with `crit` or `b64` is refused: no extension is implemented. Base64url is read in its one canonical spelling.
- A statement is read before it is shown: it must name the screen's own E_enc and E_sig, so a Front that swapped them is refused. Its times, as a completion's, are the Core's to hold at acceptance.
- A completion is never read under T's `typ`, nor a statement under the completion's, and, at `log`, is taken only with ⑤'s receipt (A35): signed by the log, an `approval` record's, binding the digests of the T approved, the assertion sent and the code.
- No key of the log's, nor of a status's or stateOf's signer set, may be one of the Core ring's, keys told apart by their kind's public members alone: a Core holding both would sign its own proof.
- A credential list is never dropped to none: an empty or unreadable one is refused, not widened to any credential.
- Hashes are SHA-256, base64url without padding.
- Each step takes only what the step before made (`ReadT`, `Mail`, `ReadCreation`, `ReadPossession`, `ReadManage`, `Continued`): a copy, or one made elsewhere, is refused. What a step hands on is frozen, its bytes aside.

## Depends on
- `sdk-core-wire` (the words, the payloads, the items' rule, the inputs), `continuation-wire` (a continuation's stages, bodies and bytes), `passkey-key-wire` (a passkey's key form and its vectors), `transparency-wire` (the receipt, the status, the stateOf, their signer sets), `flow-state-wire` (a stateOf's state, read).
- `front-core-wire`, for a test alone: the answer forms and purposes it names agree with sdk-core-wire's, the stages with continuation-wire's.
