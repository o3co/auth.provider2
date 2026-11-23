# promises

## Responsibilities
- Owns the promises' words and judges, once per boot, which promises the composition holds: from where each module says it stands, never from a list of module names.
- Refuses boot where a promise the deployment requires does not hold, naming what breaks it.

## Not here
- Where a module stands, and the setting that changes it: each module declares its own stance.
- That a module taking a contract a promise rests on declares one: the contract's owner marks it (`takersContribute`), and the kernel refuses a taker that declares none.
- Checking the operator's conditions and the receivers' duties: they are named as unchecked, never judged.

## Offers
- `promiseNames`: `front-compromise-new-authorization` (claim 1, with the session's binding), `front-compromise-client-token` (claim 2), `store-write` and `core-compromise-contained` (claim 3). `PromiseName`, one of them.
- Extension point `stances` (any number): a `Stance` names a promise, whether the module holds it, the module (`by`), and where it breaks it, the setting's key path and the reason.
- `promises`: `judgment()`, each promise in `promiseNames`' order (`PromiseJudgment`): whether it holds, its basis (`declared`) and what breaks it (`Breaking`).
- Section `promises`: `required`, the promises a deployment requires.
- At each start, one line per promise (`promises.judged`): `info` where it holds, `warn` where not, with its basis, what was not checked, and what breaks it.

## Invariants
- A promise holds only where at least one module stands holding it and none stands breaking it; none declared holds nothing.
- The basis is `declared`: the composition and its settings were checked; the operator's conditions and the receivers' duties were not, and each line says so.
- A line and a refusal name a setting by its key path and never by its value.
- A required promise that does not hold refuses boot at `promises.required.<i>`, before anything starts.

## Depends on
- `kernel`.

## Vocabulary
- promise: a claim of the provider, as a named contract a deployment holds or not.
- stance: what one module says of one promise.
