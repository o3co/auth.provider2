# path

Internal module of `passkey-management`: the first key's path made from its parts in a build.

## Responsibilities
- Takes what the path needs, makes its nonces, tokens, jobs, start, mail's side and creation, and answers its routes.

## Not here
- What each part does: internal modules `nonces`, `tokens`, `sealed`, `evidence`, `dispatch`, `issuing`, `start`, `creation`, `mail-side`, `routes`. The kinds' rule and the dropped jobs' count: the package.

## Offers
- `pathTakes`: what the path takes, which its package names among its takes. `pathOf` (the build, the evidence, the count of a job dropped) → the routes.

## Invariants
- A build is refused at `passkey-management` where `users` looks no one up by identifier, or no passkey witness is composed.
- The jobs are started with the assembly and stopped with it: its hooks come before `http`'s, so it starts before any route is served and stops once `http` has drained, waiting for the jobs the last requests put.
- What a start's job did is written as `passkey-management.start_ended`: its evidence's end, what the job did, and the faults' names alone, each once; never an address, an identifier or a subject. A job dropped or failed is a `warn` line, its error's name alone. A mail's side or a recovery refused, or met by a statement's own refusal, is a `warn` line (`mail_refused`, `recovery_refused`) with its reason's word alone.
