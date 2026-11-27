# hint

Internal module of `oidc`: its own ID token given back as a hint (`id_token_hint`, OIDC Core §3.1.2.1).

## Responsibilities
- Reads a hint's subject: an ID token the authority's ring verifies under `JWT`, of this issuer, for the client.

## Not here
- Whether the login meets the subject, and the refusal's error (`authorize`, at the start, a push and the finish). Which keys verify, and until when (`keys`).

## Offers
- `hintReader` (`keys`' `verify`, the issuer's URL) → `HintReader`: `subjectOf` (the hint, the client → `{ subject }` or `{ refused }`, the refusal saying why); the type `HintSubject`.

## Invariants
- Verified by the authority's ring as `keys` verifies a token: any key of it that still verifies, a previous one until its `expires-at`; one past it is refused (`kid_expired`). An access token (`at+jwt`) is none: its `typ` is another.
- Its `exp` is not checked (§3.1.2.2: one expired is taken): the person's tap, not the hint, authenticates. `aud` names the client, alone or in a list; `iss` is this issuer; `sub` is a string, not empty.

## Depends on
- `keys` (the type of `verify`); the package's `id-token` (`idTokenTyp`).
