# sdk-core-wire

## Responsibilities
- Holds the contract between the login screen and the Core, which the Core holds and the screen follows, the Front relaying it unread: its words, payloads' schemas, T's items from a JAR and what each hash and signature covers, once, so both sides build the same bytes.

## Not here
- Hashing, signing, sealing and verifying: the screen's SDK and the Core, each its own.
- How a request crosses the Front: `front-core-wire`.
- A passkey's public key form (its JWK, its thumbprint's input, the shared vectors): `passkey-key-wire`.
- A statement's continuation (its stages, bodies and bytes, a sealed stage's plaintext and data): `continuation-wire`. Only the info it is sealed under is here (`hpke`).

## Offers
- `typs`: the `typ` of a JAR, every statement (T, a creation, a possession: `approval+jwt`), the completion's answer (`completion+jwt`), a client assertion and a DPoP proof. `purposes`: `authorization`, `creation`, `possession`, `passkey-add`, `passkey-manage`.
- `hpke`: the suite (`DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `AES-128-GCM`), each sealing's info (the completion, the first key's request and code, a continuation's body), `completionAad` (purpose, statement's hash), and `completionBuckets`, `completionLimits`, `paddedCompletion` and `unpaddedCompletion`: how a passkey-add's or passkey-manage's completion is padded before it is sealed (internal module `completions`).
- `jarClaims`: an authorization's closed set of `items`, those a JAR must carry (`required`), and its `envelope`, the claims that are no item (`prompt` among them, which the Core reads before T is made).
- `itemsFromJar` (payload, the JAR's hash, and under PAR the `request_uri` the start named): T's items, or an error naming the claim unknown or missing, or the value not allowed; each claim an ID token's or userinfo's request asks by `null` written as `{}`.
- `payloads`: the schemas of T, the completion's answer, the `creation`, `possession`, `passkeyAdd` and `passkeyManage` statements, and what the first key's start, mail and answer seal. Types: `StatementPayload`, `CompletionPayload`, `CreationPayload`, `PossessionPayload`, `AuthorizationAnswer`, `AuthorizationItems`, `SigningKey`, `FirstKeyStage`.
- `payloads.answers`: the answers' forms the Front carries unread, whose names `front-core-wire` gives each operation: `authorization` (②'s), `statement`, `sealed` and `nonce`.
- `payloads.completions`: `passkeyAdd`, `passkeyManage` and `keyChange` (internal module `completions`). `payloads.completion` is the authorization's, its `purpose` and ⑤'s `receipt` optional.
- `versions`: the wire versions a reader speaks (1); every statement and completion names its own as `v`. A creation's `options` name the `algorithms` the ceremony offered, as COSE numbers them, each once, and may name `user_name`, the account's name a passkey shows for a subject with no identifier: a label's text, not blank.
- `canonicalText` and `challengeInput`: what a challenge covers. `firstKey`: `stages` (`start`, `mail`), `evidenceInput`, `aad` and `recoverInput`: what the evidence's value, a sealed request's additional data and a recovery's signature (the mail's nonce, the request's digest) cover.

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that build by them; no I/O, clock, randomness or state.
- A value nested however deep JSON reads it is read and written whole (`canonicalText`, T's `claims` check): no walk recurses, so no value JSON reads is a RangeError.
- Every reader parses T strictly, so a member added after a release raises `v` or waits for every reader to take it (V22); the schema does not tell T's two forms apart, the Core writing `request_uri` on every start by it and the screen holding T to its URL's.
- Every payload refuses a field it does not know; T's items are a closed set, and a JAR with any other claim beside its envelope yields no items. `request_uri` is no claim of the JAR (a JAR carrying one yields none): it is T's item under PAR alone, the start's, and absent by value.
- T's `claims` is a JSON object (OIDC Core §5.5), any other `item:claims`, and holds no null: T is signed whole, and its signer writes none. A claim an ID token's or userinfo's request asks by `null` is written `{}`, as both ask it in the default manner (OIDC Core §5.5.1), on both sides alike; any other null in `claims` is `item:claims`, though §5.5 has a member not understood ignored: that null rule alone is a stricter reading, kept as a deviation.
- The identifier goes in a statement masked alone, for display; a creation names its account by `account` or `user_name`, one alone: the first key's path by `account`, F1's by `user_name` (its subject has none), passkey-add's by either.
- A creation's `basis` fixes what its evidence hashes: the mail token (`first-key`), the approved `passkey-add` statement, or the T read before signing up (`sign-up`); `ct_hash` is `first-key`'s alone, a creation with no basis read as such.
- ②'s answer: T, its get challenge (SHA-256 of `challengeInput(T, "get")`, which the screen recomputes and uses) and `create`, an unsigned hint for F1.
- A sealed value is `{ enc, ct }`: a 65-byte uncompressed point and the ciphertext with its 16-byte tag, base64url in one spelling; a nonce is 32 bytes.
- An approval's completion binds the statement's and assertion's SHA-256, sealed under `completionAad` of the statement answered (a key change's: the `possession` for an add, the `passkey-manage` statement for a delete). A reader parses the form its request expects.
- A label is 1 to 64 code points, no control, format, surrogate or line separator.
- A creation excludes 15 credentials at most.
- `basis` and the completion's `purpose` are optional until their writers name them, then required. `prompt` is the Core's to check, before T.
- A creation names the key generation it is signed for (`kg`): one signed before a reset registers no key after it. A possession names the new key by `key_jkt`, its thumbprint, the base64url SHA-256 of passkey-key-wire's `passkeyThumbprintInput`.
- A challenge's input names its use, the evidence's its purpose, each apart from the value by a NUL.

## Depends on
- Nothing in the workspace; `zod` (a peer). Its internal module `completions`, over the building blocks in `primitives`.

## Vocabulary
- statement: what a person approves with a passkey, signed by the Core's ring; T is an authorization's.
