# keying

Internal module of `passkey-management`: a passkey-add's approval, and a key's registration after its creation, made from their parts in a build.

## Responsibilities
- Wires `registration` over `key-change`, and `approval` over `creation`, with the contracts they take, and gives their routes; writes each refusal with its reason's word alone.

## Not here
- What a stage does: internal modules `registration`, `key-change`. The routes' reading: internal module `routes`.

## Offers
- `keyingTakes`, which its package names among its own takes.
- `keyingOf` (a build) → `registerStage`, the stage `register` of `/continue` the package contributes; `signUp`, the package's `signUpCreations` (a creation of basis `sign-up` for T's hash, the new subject, T's screen, its account named by `nameOf` in `user_name` alone), and the routes `keyFinish`, `approvalStart` and `approvalFinish`, counted per source in the first key's path's window; lines `passkey-management.registration_refused` (a finish's) and `approval_refused` with its reason.
- A sign-up's creation refused for a passing failure (a count reached, busy, withdrawn) throws Unavailable, so its T keeps none.

## Invariants
- The deployment's name an approval's account shows is `account-name`, by default the mail link's host, cut to 50 characters as `account-name` is bounded.
- A key change's end is looked for up to 18 times, soon at first, then every 200 ms, as `approvals`' writer looks.

## Depends on
- `approvals`, `passkeys`, `webauthn`, `subject-revocation`, `transparency`, `users`, `kernel`; internal modules `registration`, `key-change`, `approval`, `creation`, `routes`.
