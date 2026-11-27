# pattern

Internal module of `attack-harness`: the default pattern's seed (M4) and its start, for its tests alone.

## Responsibilities
- Holds the seed: the features and axes of a whole Core, each module's configuration from its own `./testing`, the spec a harness varies (its clients, seeds, outbound, released claims, its answer to a violation, a ring of two generations from a key the test keeps, the reset's installation and signers), and its boot within its limit.
- Starts it in a process of its own, reached over the wire alone, with what the operator publishes (the key sets, the discovery document), its mail and its log lines; or in this process, on the runtime parts given (a clock, a log), the same steps after its start: its seeds imported, its key sets and discovery document published.
- Registers the clients a step needs: a relying party, a machine client of a signed registry, one naming a `jwks-uri`.
- Holds the wire's certificates for the process: one set, removed when the last hold is let go.

## Not here
- The world a step acts in (the Fronts, the people signed up): the package's internal module `world`. The roles: `roles`.
- create-app's patterns.

## Offers
- `pattern` (a spec, a mail sink) → the Core's modules and configuration; `entry`, `features`, `axes`, `previousKid`, `PatternSpec`, `SentMail`.
- `startCore` (a spec) → `StartedCore` (its port, ring, sealing key, key sets, metadata, mail, log lines, stop); `readyWithinMs`; `waitingOver` (a list, what it holds) → a wait for an item.
- `startHere` (a spec, a mail sink, runtime parts) → `Here` (the Core assembled, its port, key sets, ring, sealing key, metadata): the child process's start, which it runs.
- `registered`, `signedMachine`, `uriRelyingParty`, `signedUriMachine`, `uriMachine`: a client's record as `clients` takes it.
- `holdCertificates` → `Held` (the certificates, `letGo`).

## Invariants
- The Core composes each module by its workspace entry, imported by its path, as `combinations` names them.
- What a spec leaves out is the default pattern's: one Core generation, no installation, its features alone.
- A hold is taken before the certificates are awaited, and let go once: where getting them fails, or by its holder.
- Its files are tests' (`test/`), typed by the root's `tsconfig.attacks.json`.

## Depends on
- The package's `relay` (its start's test) and `roles` (a relying party's type); `workspace-packages`, `front-relay`'s and core-wire's `./testing`, and each composed module by its entry.
