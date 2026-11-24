# client

Internal module of `authority-rules`: a client's flow's rules (kernel-spec §6.1's client rows, V23; V21's bundle rows).

## Responsibilities
- Derives a client's start's op id and evidence elements from its evidence, reads that evidence by its client's key, and holds a client's bundle to its one access token.

## Not here
- Where a client's start and bundle sit on their op, a forged start's descendant, the entries and the prior elements: `chain`. Verifying a signature, the client's keys at a version and its own ceiling: the caller's (`Checks`, `ClientAt`).

## Offers
- `startOf` (evidence, digest) → `StartOf` (op id, elements, `ClientEvidence`) or why not; `lifetimeMs`; `thumbprintOf` (a JWK, digest); `ClientAt`; `evidenceRead`, `evidenceTimely`, `within` (the evidence read unverified, a time, a window: TimeOK's reading, for the Core before its bundle), `tokenRefusal`.

## Invariants
- A client's start's evidence is one client assertion and one DPoP proof, each a compact JWS, and nothing else. Its op id is `start:` and the digest of the canonical JSON `{assertion, proof}` of their signing inputs (header and payload as received); its elements are each signing input's digest. Neither a signature nor the evidence's order goes into either.
- Its evidence is its client's: the assertion verified by a key written in the client's record at the version named, its `iss` and `sub` the client; the DPoP proof (`typ` `dpop+jwt`) verified by that key and naming it by its thumbprint.
- Its times: the assertion's `iat` (where named) to `exp`, and the proof's `iat`, each within the evidence window of the acceptance time.
- A client's bundle issues one access token, its header and claims texts the digest the envelope names: `sub` and `client_id` the client; no `amr`, `acr` or `auth_time`; one audience; `iat` its start's acceptance in seconds; `exp` at most `lifetimeMs` past it; `cnf.jkt` its start's key where known; audience and scope within the client's own ceiling at its start's version, where the caller gives it.

## Depends on
- `transparency-wire` (the evidence, a token's digest input and reading), the package's `evidence` (`Checks`).
