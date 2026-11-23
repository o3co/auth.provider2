# registry-wire

## Responsibilities
- Holds the words of the wire between the publisher and a Core for the client registry: what one version of the registry says, as the publisher's tool signs it and the Core's registry source reads it, from one place.

## Not here
- Signing a version, and checking a signature: the publisher's tool, and the Core's registry source.
- What a section's value means and its schema: the section's owner, through `clients`.
- Where a version is kept and how a Core reaches it: the Core's registry source.

## Offers
- `registryWire.version`: a version's schema: `v`, the wire's version; `version`, a whole number from 1 that only grows; `issuedAt`, seconds since the epoch; `clients`, each with `id`, `kind` (`public` or `confidential`), `method` and `sections` (each section's value by its name).
- `registryWire.typ`: `registry+jwt`, the type a signed version's header carries.
- `registryWire.speaks`: the wire versions a reader speaks.
- `RegistryVersion` and `RegistryClient`: a version and a client as read.

## Invariants
- A protocol (G33): types, frozen constants and fixed schemas; no I/O, clock, randomness or state.
- A version refuses a field it does not know, at its top and in each client, and a client id named twice, so one version means one thing to every reader.
- A version whose `v` is not one `speaks` names is refused.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- version: one signed state of the client registry; its number orders it against every other.
