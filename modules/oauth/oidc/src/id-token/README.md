# id-token

Internal module of `oidc`: a redemption's ID token, as a part of its bundle.

## Responsibilities
- Makes the ID token `code-grant` asks for a code whose scope has `openid`: its claims, prepared with the bundle's start's acceptance time before the bundle is recorded, and signed by the authority's ring after its receipts.

## Not here
- When an ID token is asked, and the code's facts (`code-grant`). Recording the bundle, and its receipts (`token-endpoint`). Signing and the algorithm (`keys`). `c_hash` from the code's digest (`authority-rules`). The claim table (`claims`).

## Offers
- `idTokenMaker` (`IdTokenParts`: `keys`' prepare and sign, the issuer's URL, the lifetime, the subject's attributes, the pin's ID token target) → `code-grant`'s `IdTokenMaker`; `idTokenTyp`.

## Invariants
- Its claims are a closed set: `iss`, `sub`, `aud` and `azp` (the client), `iat` (the start's acceptance, in seconds), `exp` (`iat` and the lifetime), `auth_time` (the approval's record's acceptance, in seconds; one past `iat` fails the part), `nonce`, `sid` (the session's handle), `c_hash`, `amr`, `acr` (where the code has one), `esig` and `apr` (the approval's); and the table's claims released for the code's scope and what its pin asks, which never stand for any of these.
- `email_verified` is released only from what `subject-attributes` answers as vouched for by `users`. When neither source can say, no table claim is released; both are read when the part is asked, before the bundle starts: a failure to read them, or the pin gone, fails the redemption, recording nothing.
- Its digest is the SHA-256 of `transparency-wire`'s digest input of its header and claims texts, the bytes signed as they are. `typ` is `JWT`.
- Its receipt is not written into it (`txr`, with `tokens`' at L1). A signing the holder withdrew is unavailable.

## Depends on
- `authority-rules` (`tokenRules.idToken`), `code-grant` (the maker's contract), `grants` (the part), `keys`, `transparency-wire` (the digest input), `claims-selection` (the target's type), `kernel`; the package's `claims`.
