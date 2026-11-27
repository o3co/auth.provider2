# pattern

Internal module of `attack-harness`: the harness's Core, `nextgen-core` as create-app composes it, and its start, for its tests alone.

## Responsibilities
- Holds the harness's Core: `nextgen-core`'s selection (create-app's `selectionOf`), with `sign-up` and `client-credentials` beside it, which the harness attacks, and in-process places for the axes reaching an outside system (keys, audit, store, mail, clients).
- Holds each module's configuration from its own `./testing`, the spec a harness varies (its clients, seeds, outbound, released claims, whether requests are taken pushed alone, off unless asked, its answer to a violation, a ring of two generations from a key the test keeps, the reset's installation and signers), and its boot within its limit.
- Starts it in a process of its own, reached over the wire alone, with what the operator publishes (the key sets, the discovery document), its mail and its log lines; or in this process, on the runtime parts given (a clock, a log), the same steps after its start: its seeds imported, its key sets and discovery document published.
- Registers the clients a step needs: a relying party, a machine client of a signed registry, one naming a `jwks-uri`.
- Holds the wire's certificates for the process: one set, removed when the last hold is let go.

## Not here
- The world a step acts in (the Fronts, the people signed up): the package's internal module `world`. The roles: `roles`.
- The patterns themselves, and an app generated from one: `create-app`.

## Offers
- `pattern` (a spec, a mail sink) → the Core's modules and configuration; `entry`, `features`, `axes`, `previousKid`, `PatternSpec`, `SentMail`.
- `startCore` (a spec) → `StartedCore` (its port, ring, sealing key, key sets, metadata, mail, log lines, stop); `readyWithinMs`; `waitingOver` (a list, what it holds) → a wait for an item.
- `startHere` (a spec, a mail sink, runtime parts) → `Here` (the Core assembled, its port, key sets, ring, sealing key, metadata): the child process's start, which it runs.
- `registered`, `signedMachine`, `uriRelyingParty`, `signedUriMachine`, `uriMachine`: a client's record as `clients` takes it.
- `holdCertificates` → `Held` (the certificates, `letGo`).

## Invariants
- The Core composes each module by its workspace entry, imported by its path, as `combinations` names them.
- The promises it requires are the harness's own, the claims it attacks (1 and 2, but those a spec releases, and more a spec adds), not the pattern's.
- What a spec leaves out is the harness's Core's: one Core generation, no installation, its features alone.
- A hold is taken before the certificates are awaited, and let go once: where getting them fails, or by its holder.
- Its files are tests' (`test/`), typed by the root's `tsconfig.attacks.json`.

## Depends on
- The package's `relay` (its start's test) and `roles` (a relying party's type); `create-app` (`patternNamed`, `selectionOf`), `workspace-packages`, `front-relay`'s and core-wire's `./testing`, and each composed module by its entry.
