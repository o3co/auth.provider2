# routes

Internal module of `passkey-management`: the first key's path and a key's registration as the Core's routes.

## Responsibilities
- Reads the screen's JSON as `front-core-wire` sizes its fields, and answers the path's words.

## Not here
- What a stage does: internal modules `nonces`, `start`, `mail-side` and `registration`. The request's counting: `rate-limit`'s `requestsPerSource`.

## Offers
- `firstKeyRoutes` (the nonces, the start, the mail's side, the recovery, the window) → `nonce` (`POST /first-key/nonce`: a stage, `start` or `mail` → `{ nonce }`), `start` (`POST /first-key/start`: the nonce and the screen's keys and sealing, base64url → `{ sealed }`), `mail` (`POST /first-key/mail`: as the start → `{ statement }`) and `recover` (`POST /first-key/recover`: the mail's nonce, its request's digest and E_sig's signature → `{ statement }`).
- `keyRoutes` (the registration's register and finish, the window) → `continue` (`POST /continue`: the creation, stage `register` alone, a sequence number 1 to 16, the body, E_sig's signature, no `enc` or `ct` → `{ statement }`) and `keyFinish` (`POST /key/finish`: the possession and the assertion → `{ sealed: { enc, ct } }`).
- `approvalRoutes` (the approval's start and finish, the window) → `approvalStart` (`POST /approval/start`: a purpose, `passkey-add` or `passkey-manage`, and the screen's keys, base64url → `{ statement }`, counted by the source's key) and `approvalFinish` (`POST /approval/finish`: the statement and the approving key's assertion → `{ sealed: { enc, ct } }`).

## Invariants
- Each is counted per source, takes JSON alone, across origins with `content-type`, and reads no cookie.
- A field missing, repeated, not base64url in its one spelling, or of a size the wire does not give, and for a key's registration any member not a string, is `invalid_request`, with an `error_description`; every refusal of the path itself is `access_denied` alone, its reason never told.
- A start or a mail's side whose opening the keys' holder withdrew, or a statement's own refusal, is Unavailable. A continuation of a stage not taken here, `delete` or `rename`, is `invalid_request`.
