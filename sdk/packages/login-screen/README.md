# login-screen

## Responsibilities
- The login screen's SDK: what the screen runs between the person and the Core, following the screen–Core protocol (`sdk-core-wire`) and the transparency log's (`transparency-wire`).

## Not here
- What crosses the network: the screen–Core HTTP envelopes (a sealed value's encoding, each stage's request and answer, the paths, the completion's additional data, and which bytes `t_hash` and `assertion_hash` cover) wait for the protocol's review; until then the caller hands the SDK what came and sends what it gives.
- The management screen's purposes (`passkey-manage`, `passkey-add`) and a continuation's signature form: they wait for the protocol's review.
- The relying party's checks: `rp-kit`.

## Offers
- `screenKeys()`: a ceremony's fresh screen keys, E_enc (an HPKE P-256 point, `eEnc`) and E_sig (a P-256 signing key, `eSig`, as a statement carries it), their private halves not exportable (`ScreenKeys`).
- `readStatement` (compact, purpose, the Core ring's public keys, the screen keys, the issuer): the statement as its purpose's schema reads it, or why not (`signature`, `typ`, `payload`, `keys`, `issuer`).
- `challengeOf` (statement, `get` or `create`): the WebAuthn challenge's bytes.
- `readCompletion` (sealed, its additional data, the screen keys, the ring, the issuer, T's compact bytes, the assertion's bytes): the completion's answer, or why not (`open`, `signature`, `typ`, `payload`, `issuer`, `statement`, `assertion`). `Sealed`: an encapsulated key and a ciphertext.

## Invariants
- It depends on the provider's protocol packages alone (the sdk's guard).
- Shipped code runs in a browser: WebCrypto, no Node builtins.
- HPKE is the suite `sdk-core-wire` names, base mode, one message per context (sequence 0), as RFC 9180 gives it (its test vector in the tests).
- A JWS verifies with a key under that key's own algorithm alone (ES256, EdDSA, RS256, PS256), which the header must name; a key with no `alg` is taken by its curve (EC P-256, Ed25519), never an RSA key, which fits two. A key with a private member, a `use` not `sig`, `key_ops` without `verify`, or an RSA modulus under 2048 bits verifies nothing. A header with `crit` or `b64` is refused: no extension is implemented. Base64url is read in its one canonical spelling.
- A statement is read before it is shown: it must name the screen's own E_enc and E_sig, so a Front that swapped them is refused. Its times, as a completion's, are the Core's to hold at acceptance.
- A completion is never read under T's `typ`, nor a statement under the completion's.
- Hashes are SHA-256, base64url without padding.

## Depends on
- `sdk-core-wire`, `transparency-wire`.
