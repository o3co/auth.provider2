# login-screen

## Responsibilities
- The login screen's SDK: what the screen runs between the person and the Core, following the screen–Core protocol (`sdk-core-wire`) and the transparency log's (`transparency-wire`).

## Not here
- What crosses the network, as the protocol's review settled it (V22) and the protocol packages do not yet hold: each operation's request, route and name (`loginStart`, `loginFinish`, `firstKeyNonce`, `firstKeyStart`, `firstKeyMail`, `firstKeyRecover`, `approvalStart`, `approvalFinish`, `continue`, `keyFinish`: `front-core-wire`'s), and each answer's form (`statement`, `sealed`, `nonce`), the sealed value's `{ enc, ct }`, the completion's additional data (`completionAad`) and ⑤'s receipt carried in the login's completion (`sdk-core-wire`'s). Until they land, the caller hands the SDK the statement, the sealed value, the additional data and the receipt it read, and sends what the SDK gives.
- The management screen (`passkey-add`, `passkey-manage`), the continuation's signature (ES256's raw r||s over `continuationOf`), and keys as COSE_Key with `key_jkt`: they land with the protocol packages' change.
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
- Hashes are SHA-256, base64url without padding.

## Depends on
- `sdk-core-wire` (the words, the payloads, the items' rule, the inputs), `transparency-wire` (the receipt).
