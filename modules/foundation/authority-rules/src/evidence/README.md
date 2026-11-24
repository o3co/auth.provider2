# evidence

Internal module of `authority-rules`: reading a Core writer's preimage and its evidence, through the caller's verification.

## Responsibilities
- Owns each Core kind's preimage content and reads an opened preimage to the wire's form and that content.
- Reads statements and passkey assertions through the caller's `Checks`, against the writer generation's ring and the passkeys' origin.

## Not here
- What a read record must hold on its flow: `chain`. Decrypting the preimage and verifying signatures: the caller's.

## Offers
- `contents` by kind: an approval, a noEffect and an abandonment carry none; a key change the first-key path's credential and key, its COSE_Key in its one unpadded base64url spelling; a start and a bundle how they root (`code`, or `refresh` at a rotation).
- `readPreimage` (kind, value) → the preimage and its content, or the error `preimage` or `content`. `evidenceOf`, `oneOf` (a form's values, its one value).
- `statementOf` (JWS, schema, checks, context): the payload of a statement the ring signed with `sdk-core-wire`'s statement `typ`, which every statement carries. `statements`: authorization, creation, possession.
- `assertedBy` (assertion, key, statement, checks, context): the key's assertion over the statement's challenge. `within` (statement, time).
- `Checks` (`verifyJws`, `verifyAssertion`, `digest` of text or bytes, `keyThumbprint`, a key's RFC 7638 thumbprint and COSE algorithm), `Context` (ring, origin, times), `RuleTimes`.

## Invariants
- A statement is read only where it verifies by the ring the context names (the record writer's Core generation), carries the statement's `typ` and holds to its schema; a field it does not know refuses it.
- An assertion's challenge is the digest of `sdk-core-wire`'s challenge input for `get` over the statement's compact bytes; it holds only for the key's credential.
- A statement's times are seconds; an acceptance time is milliseconds.
- The key generation a first key is made for is the signed creation's `kg`, never the preimage's; a possession names the new key by `key_jkt`, its thumbprint, as `sdk-core-wire` defines it; one naming it otherwise is refused.

## Depends on
- `transparency-wire` (the preimage), `sdk-core-wire` (statements, the challenge input, `typ`); `zod`.
