# keying

Internal module of `passkey-management`: a key's registration after its creation made from its parts in a build.

## Responsibilities
- Wires `registration` over `key-change` and the contracts they take, and gives their routes; writes each refusal with its reason's word alone.

## Not here
- What a stage does: internal modules `registration`, `key-change`. The routes' reading: internal module `routes`.

## Offers
- `keyingTakes`, which its package names among its own takes. `keyingOf` (a build) → the routes `continue` and `keyFinish`, counted per source in the first key's path's window; line `passkey-management.registration_refused` with its reason.

## Invariants
- A key change's end is looked for up to 18 times, soon at first, then every 200 ms, as `approvals`' writer looks.

## Depends on
- `approvals`, `passkeys`, `webauthn`, `subject-revocation`, `transparency`, `kernel`; internal modules `registration`, `key-change`, `routes`.
