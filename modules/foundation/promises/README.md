# promises

## Responsibilities
- Owns the promises' words and judges, once per boot, which promises the composition holds: from where each module says it stands, never from a list of module names.
- Refuses boot where a promise the deployment requires does not hold, naming what breaks it.
- Owns the words of what a first key's evidence trusts, and tells, apart from the judgment, each kind of that evidence composed: what it trusts and how strong it is.

## Not here
- Where a module stands, and the setting that changes it: each module declares its own stance.
- That a module taking a contract a promise rests on declares one: the contract's owner marks it (`takersContribute`), and the kernel refuses a taker that declares none.
- Checking the operator's conditions and the receivers' duties: they are named as unchecked, never judged.
- Checking an evidence kind, and the values of its strength: the module that checks it.

## Offers
- `promiseNames`: `front-compromise-new-authorization` (claim 1, with the session's binding), `front-compromise-client-token` (claim 2), `store-write` and `core-compromise-contained` (claim 3), and `no-client-subject-token` (no grant through the token endpoint gives a token whose subject is a client). `PromiseName`, one of them.
- Extension point `stances` (any number): a `Stance` names a promise, whether the module holds it, the module (`by`), and where it breaks it, the setting's key path and the reason.
- `promises`: `judgment()`, each promise in `promiseNames`' order (`PromiseJudgment`): whether it holds, its basis (`declared`) and what breaks it (`Breaking`).
- Section `promises`: `required`, the promises a deployment requires.
- `trustedNames`: what a first key's evidence trusts, `inbox`, `password`, `device` and `former-idp`; `Trusted`, one of them.
- Extension point `evidenceKinds` (keyed by kind, the name `first-key` keys its `firstKeyEvidence` by): an `EvidenceKind` names the kind, the module that checks it (`by`), what it trusts, its `Strength` (where it changed, the weaker under the same name, as the deployment declares while keys bound under it live), and `past`, only for a kind no longer composed whose keys live on.
- `EvidenceKind`'s `alone`, one meaning alone: a key may have been bound by this kind with no other beside it. Any kind may carry it.
- `Strength`, in promises' words: `guesses` (a count per window, on each instance), `secret` (bits, lifetime, used once), `code` (digits, windows either side, guesses), `key` (whether it verifies its user), `issuer` (the issuer, the acr asked).
- `evidence`: `kinds()`, the kinds declared, by name, frozen; at each start, one `info` line per kind (`promises.evidence`), its strength said in one fixed order.
- At each start, one line per promise (`promises.judged`): `info` where it holds, `warn` where not, with its basis, what was not checked, and what breaks it.

## Invariants
- A promise holds only where at least one module stands holding it and none stands breaking it; none declared holds nothing.
- The basis is `declared`: the composition and its settings were checked; the operator's conditions and the receivers' duties were not, and each line says so. The lines of `no-client-subject-token` and `front-compromise-client-token` also name issuance not through the token endpoint as not checked.
- A promise's line and a refusal name a setting by its key path and never by its value; an evidence line says its strength's values, an issuer's URL among them.
- A required promise that does not hold refuses boot at `promises.required.<i>`, before anything starts.
- An evidence kind holds no promise and breaks none: the judgment is the stances' alone. A kind off its shape refuses boot at `promises.evidence-kinds:<kind>`, naming the first part off it: trusting nothing, a word not of `trustedNames` or one twice, a blank name or module, or a strength not of `Strength`'s (each count a whole number from 1). So does one name declared twice.

## Depends on
- `kernel`.

## Vocabulary
- promise: a claim of the provider, as a named contract a deployment holds or not.
- stance: what one module says of one promise.
- evidence kind: one way a first key may be bound, checked by its own module, which declares what it trusts and its strength.
- strength: how hard a kind is to pass without what it trusts, as values in promises' words; guesses multiply by the instances.
- client subject token: a token whose subject is a client, issued on the client's own key rather than on a user's approval.
