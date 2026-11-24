# clients-registry

## Responsibilities
- Contributes a client source to `clients`: the clients of the registry version the publisher signed, read from a file once at boot and checked before any is answered.
- Declares where it stands on the promise its clients bear on: a version comes as a file the Core reads, so it breaks it.

## Not here
- Signing a version: the publisher's tool. What a version holds and its type: `registry-wire`.
- Checking a JWS signature: `keys`' `verifyJws`. Reading the key material: `keys`.
- What each section means, and refusing a record whose sections fail: each owner, and `clients`.
- Delivering a new version: none is read after boot.

## Offers
- Composition definition only: a contribution to `clients`' `clientSources`, and a stance (`promises`' `stances`).
- Operator section `clients-registry`: `file` (the path of the signed version), `publisher-key` (the publisher's public key as a JWK, with its `kid` and its `alg`) and `min-version` (the least version number taken), each required.
- As the one adapter of `clients`, it is composed wherever `clients` is; a composition of the operator's registered clients alone chooses the owner for its axis (`axes: {"@mod/clients": "@mod/clients"}` in `combinations`' `composed`), and needs no registry.
- At start, the line `clients-registry.read` (`info`): the version number read and how many clients it holds.

## Invariants
- Boot is refused, never left with no clients, where:
  - `publisher-key` is no public JWK with a `kid` and an `alg`, `EdDSA` over Ed25519 or `ES256` over P-256, that may verify signatures (`clients-registry.publisher-key`);
  - the file cannot be read, its compact JWS does not verify under `publisher-key` (the `kid` it names, the `alg` the key names), its signed header's `typ` is not `registryWire.typ`, or its payload does not fit `registryWire.version` (`clients-registry.file`);
  - its version number is below `min-version` (`clients-registry.min-version`).
- A refusal names the setting's key path and why, never a path, an id or a value read.
- The file is read once, at boot; a version written after it changes nothing until the next boot.
- A client is answered as the version holds it, mapped field by field into `clients`' record; `clients` holds it to each section's schema at request time, and a client the operator registered under the same id wins.
- It stands breaking `core-compromise-contained` at `clients-registry.file`: a version reaches the Core as a file it reads at boot, not on the log's publisher flow, so no one outside can check which version the Core answered by.
- It holds nothing beyond what it read, so it is safe on many instances given the same file on each.

## Depends on
- `kernel`, `clients` (the source point and the record), `keys` (`verifyJws`, `publicJwk`, `verifiesUnder`), `promises` (the stance), `registry-wire` (the version and its `typ`), `zod`; Node's built-ins only.

## Vocabulary
- version: one signed state of the client registry, as `registry-wire` names it.
- publisher: the party outside the Core that signs each version.
