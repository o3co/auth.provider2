# keys-local

## Responsibilities
- Holds the keys of `keys`' rings in the Core's own process, read at boot from its section or from files, and signs and agrees with them as the keys axis asks: the adapter for development and trials.
- Declares where it stands on the promise that rests on keys no one can take out of their holder.

## Not here
- What the keys mean, which kid signs, and how a JWS or a sealing is made: `keys`.
- Keys a compromised Core cannot take out: another adapter of the keys axis.

## Offers
- Composition definition only: the holder of the keys axis (`keyHolders`), and a stance (`promises`' `stances`).
- It is not the axis's default, which is the strong side: a development composition names it to compose it.
- Operator section `keys-local`: `keys`, each a `kid` and the key as PEM, written in `pem` or in the file `file` names.
- `powers`: neither withdrawable nor counted outside the Core.

## Invariants
- A private PEM signs (Ed25519 under EdDSA, P-256 under ES256, RSA under RS256) and a P-256 one agrees; a public key or a certificate only verifies, its key taken out of it and nothing of the certificate checked. Only a key's public half leaves the module.
- A `pem` not written as PEM is refused by the section, before it is read; one it cannot read as a key, the example's `REPLACE-` placeholder among them, and a file it cannot read, refuse boot at the key's path, never naming the value.
- An entry holds exactly one of `pem` and `file`, and a kid once.
- It stands breaking `core-compromise-contained`: its keys are in the Core's memory, so a compromised Core takes them out and signs on after it is stopped, and no signing is counted outside it.
- It holds nothing beyond what it read, so it is safe on many instances given the same keys on each.

## Depends on
- `kernel`, `keys`, `promises`, `zod`; Node's built-ins only.
