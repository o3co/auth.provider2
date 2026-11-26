# clients

## Responsibilities
- Looks up and authenticates clients, checking and freezing their records at the boundary, with built-in methods `client_secret_basic`, `client_secret_post` and `none` (internal module `methods`), and freezing the registry every taker shares, so none reassigns a member for the others.

## Not here
- What each metadata field means: the module that reads one contributes it as a section, and its default applies to a client without it.
- Filling a section from a client's metadata document: `client-documents`, with each section's owner.

## Offers
- `find` (id → client or none) and `authenticate` (request → client or a typed refusal, never null); both throw unavailable when a source is unavailable. A caller records a refusal through `recordRefusedAuthentication` (its audit, the request, the refusal) as `client.authentication.failure`, with `reason` and `source`, never the client id claimed; declared in `./audit-events`.
- `clientIdNameable` (id → whether a client can have it: 1 to 64 visible ASCII characters): a source holds its own ids to it and refuses boot for one that fails, as `clients` never asks for nor lists such an id.
- `checkRecord` (record → where it fails, or nothing): the checks `find` holds a source's record to (the registered rule, a known method that is no secret method, each section's schema), each failure a path from the record's root (`sections.consent.uri`), never a value or message; it rejects when a schema throws.
- An authenticated answer carries the challenges for a later 401 to that client: its method's, or every method's when its method has none; and what its method verified (`proof`, `Verified`), unread, where it verified one, marked `assertion` for an assertion method's.
- `bare` (request → whether it carries nothing a client authenticates with, whichever methods are composed). `authenticate`'s `no_credentials` says only that no composed method claimed the request.
- `registered` (→ the clients the operator registered, in the settings' order, the `i`th at `clients.registered.<i>`), for a boot check that names one by its place, never its id; `listed` (→ the clients of the sources that list theirs, as `registry`'s card says), for a boot check that names none by id.
- `methods` names the usable authentication methods, built in and contributed; `signingAlgorithms` names the algorithms they take signed credentials in.
- A client gives its metadata by section, and says whether the operator registered it or another source named it, the registry version its record came from where its source names one, and that the version is one its publisher signed where its source declares all its records are (`signed`).
- Asking a client for a section no module contributed throws; it never answers undefined.
- Extension point `authMethods`: a method names its challenge for a refusal and its signing algorithms (at least one where it names any, never the JWS algorithm `none` in any case: boot refuses a method that breaks either), may say a request carries its credentials malformed, and may say it authenticates by an assertion (RFC 7521), when it names at least one signing algorithm (boot refuses one that does not).
- A method may say its credentials need a key the client alone holds (`keyHeld`), a signature by an asymmetric algorithm: boot refuses one naming no signing algorithm, or one not an asymmetric JWS algorithm (RS, PS or ES of 256, 384 or 512, ES256K, EdDSA, Ed25519, Ed448), its algorithms held as checked. Left out, it declares no such hold; the built-in methods declare none.
- Extension points `clientSources` and `metadataSections`; a section may give `checkAtBoot`, which takes a registered client's value of that section after the schema, and the client that holds it, and may give a reason to refuse boot.
- Operator section `registered`: a list of `id` (1 to 64 visible ASCII characters), `kind` (`public` or `confidential`), `method` and `sections` (values by section name); built-in section `client-secret` holds `hash`, a bcrypt or scrypt hash in the forms `secret-hash` reads.
- Its stance on `promises`' `front-compromise-client-token` (claim 2): broken by a registered client of a secret method, named by its place, or a contributed method declaring no key held; held otherwise (internal module `methods`).
- `./testing`: `confidentialClient` and `publicClient` (test clients; `clientSecret` is the former's secret) and `clientsConfig`.

## Invariants
- `none` is the method only when no other method claims the request; an Authorization header no method reads claims nothing.
- `bare` is false for an `authorization` header, a client certificate (a malformed one included), any of `client_id`, `client_secret`, `client_assertion` and `client_assertion_type` sent at all (empty, repeated or not a string included), and anything a composed method claims or finds malformed; a field only a method not composed reads cannot be told.
- `checkAtBoot` sees each registered client that carries the section, and never a source's client, which the section's owner checks at request time.
- A `checkAtBoot` reason refuses boot at `clients.registered.<i>.sections.<name>`, which names the client by its place and the section; the reason is the check's own, unchanged, so it never holds a configuration value, the client's id included.
- An unknown client, an invalid record and another method's client are refused only after the work the claimed method's credentials would cost (`decoy`; a secret's is the checker's decoys), so the time tells no client id apart.
- How a record is read, which client an id names, the one method a request uses, the order of refusals and a refusal marked `assertion`: the internal module `registry`'s card.
- How each built-in method reads a request, and how a secret is checked: the internal module `methods`' card.

## Depends on
- `kernel`, `http`, `secret-hash`, `audit` (the declaration), `request-source` (the source), `promises` (the stance)

## Vocabulary
- client: an id, a kind (public or confidential), an authentication method, and metadata by section.
- source: where client records come from; registration is built in, and others contribute to `clientSources`.
