# path

Internal module of `first-key`: the first key's path made from its units in a build.

## Responsibilities
- Checks at boot what the path needs, makes its jobs, and joins its units, each built over its own contracts, into its routes.

## Not here
- What each unit does, and what it takes: internal modules `nonces`, `tokens`, `sealed`, `evidence`, `dispatch`, `issuing`, `start`, `mail-side`, `routes`. The creation: `passkey-management`'s `firstKeyCreations`. The kinds' rule and the dropped jobs' count: the package.

## Offers
- `pathTakes`: what the path and its units take, which its package names among its takes. `pathOf` (the build, the evidence, the count of a job dropped) → the routes.

## Invariants
- A build is refused at `first-key` where `users` looks no one up by identifier, no passkey witness is composed, or webauthn takes no ceremony from the mail link's origin.
- The jobs are started with the assembly and stopped with it: its hooks come before `http`'s, so it starts before any route is served and stops once `http` has drained, waiting for the jobs the last requests put.
- What a start's job did is written as `first-key.start_ended`: its evidence's end, what the job did, and the faults' names alone, each once; never an address, an identifier or a subject. A job dropped or failed is a `warn` line, its error's name alone. A mail's side or a recovery refused is a `warn` line (`mail_refused`, `recovery_refused`) with its reason's word alone.
