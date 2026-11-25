# continuation-wire

## Responsibilities
- Holds a statement's continuation, what the screen's E_sig sends after a statement stage by stage (§C.2, §C.6, V24): the stages' names, each stage's body, what E_sig signs and the bytes a body's hash covers, and a sealed stage's plaintext and additional data, from one place for the screen's SDK and the Core.

## Not here
- The statement a continuation follows, its purposes and the completions that answer it: `sdk-core-wire`.
- HPKE's suite and the info a sealed body is sealed under: `sdk-core-wire`'s `hpke`.
- The `continue` operation that carries a stage, and the stage's value on the wire: `front-core-wire`.
- Signing, sealing, opening and verifying: the screen's SDK and the Core.

## Offers
- `continuations`: `stages` (`register`, `delete`, `rename`, `sign-up`; `ContinuationStageName`); `of` (stage, statement's hash, sequence, body's hash), what E_sig signs, and `signature` (ES256's raw r||s over its UTF-8); `bodies` (a delete's, a rename's and a sign-up's, `{}`); `bodyText` (stage, body): the canonical text a body's hash covers, none for a stage with no body of its shape (a register's hash covers the response's text as received).
- `continuations`' sealed stages (`sealed`, `SealedStageName`: `delete`, `rename`): `aad` (stage, statement's hash, sequence), `plainBytes`, `plainOf` (stage, body, signature) and `readPlain` (stage, opened text).

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that build by them; no I/O, clock, randomness or state. It depends on no package of the workspace (G2, G6): its canonical text, its base64url spelling and a label's characters are its own rules, the same as sdk-core-wire's, which a package reading both holds to agree.
- Each stage signs apart: `of` names the stage, and a register's input is the same bytes as before the stages were named.
- A body is strict: a credential id is base64url in one spelling, 1364 characters at most (1023 bytes); a label is 1 to 64 code points, no control, format, surrogate or line separator.
- A sign-up's body travels unsealed as its text: `{}`, the one spelling `bodyText` gives, which the Core takes alone; its hash covers that text.
- A sealed stage's body goes sealed, its signature inside: `{ body, sig }`'s canonical text padded with spaces to `plainBytes`, bound to stage, statement hash and sequence, so only the stage shows. An opened text reads only at that length, canonical then spaces alone, of its stage's shape.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- continuation: a step E_sig signs after a statement, by its stage. stage (段): register, delete, rename or sign-up (F1's, on an authorization's T). sealed stage: one whose body and signature only the Core opens.
