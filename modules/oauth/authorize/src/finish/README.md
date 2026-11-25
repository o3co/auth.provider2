# finish

Internal module of `authorize`: the route of a login's finish (⑤⑥).

## Responsibilities
- Uses the person's assertion over T once, judges the issuance, opens the session, has `code-grant` make a code, has `approvals` put the approval on the subject's flow and seal the completion, and roots the code in that record before the completion is answered.

## Not here
- T, its use and its completion (`approvals`). The code, its record and redemption (`code-grant`). The session's record (`session`). The policies (`tokens`). Reading the binding asked for ahead (`sender-binding`).

## Offers
- `finishing` (`FinishParts`) → the handler; `finishRoute` (the parts taken from the composition, the issuer, the delegation's length, the window) → the route; `finishTakes`, the contracts it takes.

## Invariants
- The amr a passkey's login carries (`passkeyAmr`, to `acr`'s `amrSources` as `authorize.passkey`): `pop` and `user`, what a passkey's assertion proves (a key held, the person present); not `hwk`, as no attestation is taken, nor `mfa`, as user verification is the authenticator's own word.
- The steps run in this order:
  - the approval used, the scope and audience within the client's allowance, the policies, an OpenID request's claims selected (`claims`; a `sub` asked of another subject, or an essential acr the login does not meet, is `access_denied`, no session opened);
  - the session (from the statement's issue: `provenSince`, and `endsAt` that and the delegation's length), the code made with no root, carrying the acr a passkey's login meets (`acr`'s table, given by the module), its claims pinned to it;
  - the approval completed, the code rooted in its record with the approval's `esig`, `apr`, acceptance and statement's hash, the completion answered.
- A completion goes out only after its code is rooted: the finish that made the code answers it, then publishes it, and a resent finish is given it only once published. A resend before that is answered `temporarily_unavailable` and makes no code.
- A code made where the finish fell between completing and rooting is never rooted, as no finish roots a code but the one that made it: never given out, never redeemed, it ends with its lifetime, the approval used. Two finishes at once make two codes; only the one `approvals` keeps is completed and rooted, the other's finish answering `access_denied`.
- What a code needs is checked again before the session opens (`code-needs`: the code grant, the challenge, the scope and the resource allowed, the binding asked for ahead); a session opened for a finish that gives no completion is closed.
- A login with a passkey is named by `amr` `pop` and `user`, what its assertion proves: a key held (its signature) and the person present (its flags). No `hwk`, as no attestation is taken and a synced passkey is bound to no one device; no `mfa`, as verifying the user is the authenticator's own word, and strength is `acr`'s.

## Depends on
- `kernel`, `approvals`, `clients`, `code-grant`, `tokens`, `session`, `http`, `rate-limit`; the package's `claims` and `code-needs`.
