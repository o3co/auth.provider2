# sign-up

Internal module of `login-screen`: F1's path on the screen (sign-up, the credential first; §3.13), from a `ReadT`.

## Responsibilities
- Sends T's `sign-up` continuation and reads the creation it answers, for the first key's steps to go on.

## Offers
- `signUp`:
  - `continuation` (a `ReadT`, the screen keys T names): what `continue` sends, the stage `sign-up`, sequence 1, the body `{}` and E_sig's signature over continuation-wire's `of` (T's hash, 1, the body's hash); or why not. One per T (sequence 1 alone): a resend, signed again or not, is answered with what the Core kept, the creation or a final refusal (`pending` while the first runs).
  - `readCreation` (the creation, the `ReadT`, the ring, the screen keys T names, the issuer): a `ReadCreation` of `basis` `sign-up`, its evidence T's hash, that `firstKey`'s next steps take (`createOptions`, `continuation`, `readPossession`); its key change's purpose is `sign-up`. Or why not.
  - T is approved after by the registered key: `authorization.assertionOptions` given that credential alone. Where the sign-up stage's refusal is final, the screen starts the authorization again; where T's approval by a key held before is refused, the page may let the person try again, and once it gives up it carries the refusal (`refusal`).

## Depends on
- `continuation-wire`.
- The package's `authorization` (a `ReadT`, its denial), `first-key` (`ReadCreation`), `statement`, `jws`, `keys` and `bytes`.
