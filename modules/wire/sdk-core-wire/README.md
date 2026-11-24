# sdk-core-wire

## Responsibilities
- Holds the contract between the login screen and the Core, which the Core holds and the screen follows; the Front relays it unread. Its words, the payloads' schemas, the rule that makes T's items from a JAR, and the inputs each hash and signature covers are written here once, so both sides build the same bytes.

## Not here
- Hashing, signing, sealing and verifying: the screen's SDK and the Core, each its own.
- How a request crosses the Front: `front-core-wire`.

## Offers
- `typs`: the `typ` of a JAR, every statement (T and the first key's creation and possession: `approval+jwt`), the completion's answer (`completion+jwt`, apart from them), a client assertion and a DPoP proof. `purposes`: `authorization`, `creation` and `possession`.
- `hpke`: the suite (`DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `AES-128-GCM`) and the info of each sealing: the completion, the first key's request and its code.
- `jarClaims`: an authorization's closed set of `items`, those a JAR must carry (`required`), and its `envelope`, the claims that are no item.
- `itemsFromJar` (payload, the JAR's hash): T's items, or an error naming the claim unknown or missing, or the value not allowed.
- `payloads`: the schemas of T, the completion's answer, the `creation` and `possession` statements, and what the Core opens of the first key's start and mail's side and the screen of the start's answer. Their types: `StatementPayload`, `CompletionPayload`, `CreationPayload`, `PossessionPayload`, `AuthorizationItems`, `SigningKey`, `FirstKeyStage`.
- `versions`: the wire versions a reader speaks (1); every statement and completion names its own as `v`. A creation's `options` name the `algorithms` the ceremony offered, as COSE numbers them, each once.
- `keyThumbprintInput` (a JWK): what a passkey's thumbprint (RFC 7638, RFC 8037) is the SHA-256 of, the JWK's required members sorted; none for a JWK that is not a passkey's (`PasskeyJwk`).
- `canonicalText`, `challengeInput` and `continuationInput`: what a challenge and a continuation's signature cover. `firstKey`: the first key's `stages` (`start` and `mail`), `evidenceInput` and `aad`, what the evidence's value and a sealed request's additional data cover.

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that build by them; no I/O, clock, randomness or state.
- Every payload refuses a field it does not know; T's items are a closed set, and a JAR with any other claim beside its envelope yields no items.
- The identifier never goes into a statement but masked, for display alone.
- A creation names the key generation it is signed for (`kg`), so a creation signed before a reset cannot register a key after it. A possession names the new key by `key_jkt`, its thumbprint, the base64url SHA-256 of `keyThumbprintInput`.
- A passkey's key is ES256 (P-256), EdDSA (Ed25519 alone) or RS256 (a modulus of 2048 to 4096 bits, exponent 65537). A JWK holds its thumbprint's members alone, each in its one unpadded base64url spelling: x and y 32 bytes, an odd modulus whose first byte is not 0 (refused, never cut). A P-256 point off its curve is refused, each side's crypto checking it; an Ed25519 x is taken as its 32 bytes, one that is no point failing at its signature.
- A key travels as its COSE_Key bytes: CTAP2's canonical CBOR, a map of its key type's labels alone (1, 3, -1, -2, and -3 for EC2), in order, each once, of definite lengths, its integers shortest; read whole in the authenticator data, after which come only extensions, where flagged. The screen may read the SPKI instead, its algorithm's identifier and lengths checked, and reads the COSE_Key where the browser gives no SPKI.
- `test/keys.vectors.json` holds each algorithm's key as COSE, SPKI and JWK with its thumbprint, and keys refused; every reader of this form runs them.
- A challenge's input names its use, and the evidence's its purpose, each apart from the value by a NUL.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- statement: what a person approves with a passkey, signed by the Core's ring; T is an authorization's.
