# routes

Internal module of `passkey-management`: a key's registration and a live key's approval as the Core's routes.

## Responsibilities
- Reads the screen's JSON by `front-core-codec`'s `requestOf`, every field held to `front-core-wire`'s spec, and answers its routes' words.

## Not here
- What a stage does: internal modules `registration`, `approval` and `managing`. The request's counting: `rate-limit`'s `requestsPerSource`.

## Offers
- `continueRoute` (the stages by their word, the window, where a refusal is told) → `POST /continue`: the statement, a stage `continuation-wire` names, a sequence number 1 to 16, and the body and E_sig's signature in the clear, or `enc` and `ct` for a stage `continuation-wire` seals, `ct` exactly its padded plaintext and the tag long (2064 bytes).
  - It is handed with the statement's hash and the source's key to the stage contributed; its answer is `{ statement }` or `{ sealed }` as the stage is clear or sealed, as `front-core-wire`'s forms give it.
- `stagesOf` (the stages contributed, a refusal) → them by their word, boot refused where two continue one stage.
- `keyRoutes` (the registration's finish, the window) → `keyFinish` (`POST /key/finish`: the possession and the assertion → `{ sealed: { enc, ct } }`).
- `approvalRoutes` (the approval's start and finish, the window) → `approvalStart` (`POST /approval/start`: a purpose, `passkey-add` or `passkey-manage`, and the screen's keys, base64url → `{ statement }`, counted by the source's key) and `approvalFinish` (`POST /approval/finish`: the statement and the approving key's assertion → `{ sealed: { enc, ct } }`).

## Invariants
- Each field is taken only as front-core-wire's spec of its operation holds it (`continue`, `keyFinish`, `approvalStart`, `approvalFinish`), read by `requestOf`, never a copy, so the Core takes in process what a Front carries; a stage and a purpose by the wire's own words.
- Each is counted per source, takes JSON alone, across origins with `content-type`, and reads no cookie.
- A field `requestOf` refuses (missing, repeated, of a size or characters the wire does not give, bytes not in their one base64url text, a number past its count, a text with a control character or a lone surrogate), a continuation numbered 0 or sealed as its stage is not, and any member not a string, is `invalid_request`, with an `error_description`; every other refusal is `access_denied` alone, its reason never told.
- A continuation of a stage no module continues here is `invalid_request`; a stage's refusal is `access_denied` alone, its stage and reason told to the package's log (`continue_refused`); an answer of another form than the wire gives the stage is a fault. Each stage's checks of the fields are here, once: a stage's own module checks only what its step needs.

## Depends on
- `front-core-codec` (the reading), `front-core-wire` (the operations and their words), `continuation-wire` (the stages' words), `approvals` (the screen's keys), `http`, `rate-limit`, `kernel`.
