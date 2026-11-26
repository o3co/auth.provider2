# routes

Internal module of `first-key`: the first key's path as the Core's routes.

## Responsibilities
- Reads the screen's JSON by `front-core-codec`'s `requestOf`, every field held to `front-core-wire`'s spec, and answers the path's words.

## Not here
- What a stage does: internal modules `nonces`, `start`, `mail-side`. The request's counting: `rate-limit`'s `requestsPerSource`.

## Offers
- `firstKeyRoutes` (the nonces, the start, the mail's side, the recovery, the window) → `nonce` (`POST /first-key/nonce`: a stage, `start` or `mail` → `{ nonce }`), `start` (`POST /first-key/start`: the nonce and the screen's keys and sealing, base64url → `{ sealed }`), `mail` (`POST /first-key/mail`: as the start → `{ statement }`) and `recover` (`POST /first-key/recover`: the mail's nonce, its request's digest and E_sig's signature → `{ statement }`).

## Invariants
- Each is counted per source under its own name (`first-key.nonce`, `.start`, `.mail`, `.recover`), takes JSON alone, across origins with `content-type`, and reads no cookie.
- A request whose fields `requestOf` refuses, missing, repeated, of a size or characters the wire does not give, or bytes not in their one base64url text, is `invalid_request`, with an `error_description`, before any nonce is used; every refusal of the path itself is `access_denied` alone, its reason never told.
- A start or a mail's side whose opening the keys' holder withdrew is Unavailable.

## Depends on
- `front-core-codec` (the reading), `front-core-wire` (the operations), `sdk-core-wire`, `http`, `rate-limit`, `kernel`.
