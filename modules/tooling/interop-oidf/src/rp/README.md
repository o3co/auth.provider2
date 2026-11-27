# rp

Internal module of `interop-oidf`: the harness's relying party, for its tests alone.

## Responsibilities
- Plays a conforming client of nextgen, and a login's start sent with two made-up screen keys (by value, by a `request_uri` or with neither: what the word table's tests send, which call up refusals no screen of the screen role's pages would send): a private_key_jwt key of its own, a DPoP key of each authorization's own, JARs as nextgen asks them (`response_mode=form_post`, `jti`, `nbf`, a short `exp`, `dpop_jkt`), pushed by PAR, codes exchanged with PKCE and DPoP.
- Makes the record the operator registers for it: its keys, redirect URI and grants by their owners' `./testing`, and `sender-binding`'s one setting written as the operator writes it.

## Not here
- The provider it speaks to: `scene`. The login screen's page, its authenticator and the person: the screen role.
- What the suite sends: the suite's own client.

## Offers
- `relyingParty` (its client id, its redirect URI, the provider read when it signs) → `RelyingParty`: `registered` (its record), `authorization` (a `JarChange`: items replaced, claims dropped, the header's `typ`) → `Started` (its state, nonce, PKCE verifier, JAR, DPoP key), `par` (proved under a nonce where asked, or by another key), `start` (a login's start, by value, by `request_uri` or neither, with screen keys), `token`, `refresh`, `assertion`.
- `send`: a request sent, once more under the DPoP nonce where the provider asks one, and whether it asked. `screenKeys`: a screen's two keys as a start carries them. `dpopKey` (its proofs, each made wrong by a `ProofChange` where a test asks, still signed by the key), `es256`, `thumbprint`.
- Its tests hold the word table (`words`) to the product: every word's request is sent to a scene (one taking a JAR by value for the words a login's start answers only then) and answered in the table's words, read as the table's row; a word added to the table with no request fails. `refresh-dpop-bound`'s word is held by a refresh token never issued; that it is the row's needs one issued.

## Invariants
- An authorization carries every item nextgen requires, so a refusal of one is of what `JarChange` changed alone.
- Each authorization has a DPoP key of its own: a family is bound to one key, and a key to one family (Q27).
- Its files are tests' (`test/`).

## Depends on
- `scene` (`startScene`, `ask`), `words` (its tests); `client-assertion`, `client-allowance`, `redirect-uris` (each by `./testing`), `sdk-core-wire` (`typs`).
