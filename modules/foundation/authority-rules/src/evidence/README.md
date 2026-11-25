# evidence

Internal module of `authority-rules`: reading a Core writer's preimage and its evidence, through the caller's verification.

## Responsibilities
- Owns each Core kind's preimage content and reads an opened preimage to the wire's form and that content.
- Reads statements and passkey assertions through the caller's `Checks`, against the writer generation's ring and the passkeys' origin.

## Not here
- What a read record must hold on its flow: `chain`. Decrypting the preimage and verifying signatures: the caller's.

## Offers
- `contents` by kind: an approval, a noEffect and an abandonment carry none; a key change (`first`, the first-key path; `add`, a passkey-add) its credential and key, its COSE_Key in one spelling; a start and a bundle how they root (`code`, a code's start with the code's digest and client, both required from V24, so a start written without them is refused (no such log exists before 0.1.0); `refresh` at a rotation; or `client`), a client's bundle its access token's header and claims texts.
- `readPreimage` (kind, value) → the preimage and its content, or the error `preimage` or `content`. `evidenceOf`, `oneOf` (a form's values, its one value).
- `statementOf` (JWS, schema, checks, context): the payload of a statement the ring signed with `sdk-core-wire`'s statement `typ`, which every statement carries. `statements`: authorization, passkey-add, creation, possession. `continuationOf`: a continuation's canonical JSON (sequence number, body, signature).
- `assertedBy` (assertion, key, statement, checks, context): the key's assertion over the statement's challenge. `within` (statement, time).
- `Checks` (`verifyJws`, `verifyAssertion`, `digest` of text or bytes, `keyThumbprint`, a key's RFC 7638 thumbprint and COSE algorithm, `attestedKey`, a `create()` response's credential and new key, read, `verifyEsig`, a screen's continuation signature by its E_sig; `selfCeiling`, a client's own ceiling where the caller gives it): every assembly gives all but `selfCeiling`, the Core's and a monitor's alike.
- `Context` (ring, origin, times), `RuleTimes` (with `evidenceWindow` where the caller gives it).

## Invariants
- A statement is read only where it verifies by the ring the context names (the record writer's Core generation), carries the statement's `typ` and holds to its schema; a field it does not know refuses it.
- An assertion's challenge is the digest of `sdk-core-wire`'s challenge input for `get` over the statement's compact bytes; it holds only for the key's credential.
- A statement's times are seconds; an acceptance time is milliseconds.
- The key generation a first key is made for is the signed creation's `kg`, never the preimage's; a possession names the new key by `key_jkt`, its thumbprint, as `sdk-core-wire` defines it.

## Depends on
- `transparency-wire` (the preimage), `sdk-core-wire` (statements, the challenge input, `typ`); `zod`.
