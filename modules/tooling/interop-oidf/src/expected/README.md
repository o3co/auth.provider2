# expected

Internal module of `interop-oidf`: a run's expected results, in the ledger's keys.

## Responsibilities
- Holds, for each module a run's plan runs under its variant, what the suite reports and how that is read, the module's whole and each refusal it meets.
- Refuses a file of them before the suite starts where any entry may not be taken.

## Not here
- Judging a run by them: `results`. The keys a run's requests compute (a JAR's missing claims): `results` too, shown beside the observed, never compared with an entry.
- The ledger and its keys: `deviations`. A refusal's words and what they say: `words`.

## Offers
- `Expected`: the module, its variant, the suite's `result` (`SuiteResult`), the module's `reading` (`Reading`), its refusals, and the FAILURE and WARNING conditions (`ExpectedCondition`: the `src`, its keys, none where unconfirmed).
- `ExpectedRefusal`: the block by the suite's message for it, refuser, place, `status`, the words (none for an answer of no body), and its reading (`RefusalReading`): `observed` (one row, its words that row's alone), `own` (the condition the module tests) or `unconfirmed` (the rows its words might be, where known).
- `expectedProblems` (a value, the ledger's keys) → why it may not be taken; `expectedOf` (a text, the keys); `expectedFor` (a run, the keys): the package's `expected/<run>.json`; `expectedPath`.

## Invariants
- Plan §6's refusals of a run: a key the ledger has not, a key twice, a field empty or of another type, a wildcard (`*`), the same module twice under one variant, a variant that is no object of texts. A field none has is refused too.
- A reading has its results: `passed` PASSED; `own-condition` PASSED or REVIEW, by an `own` refusal; `before-wall` PASSED, by an `observed` one; `explained` FAILED, WARNING or REVIEW, every condition keyed, a cause observed; `unconfirmed` any but SKIPPED, by a refusal or a condition the words leave apart; `skipped` SKIPPED, nothing met.
- A FAILED names its failures, a WARNING its warnings, a PASSED none; a condition's keys are ones a refusal of the entry shows observed; `passed` and `own-condition` show no row. A REVIEW `own-condition` is approved; `explained`, a failure explained; `unconfirmed`, left unapproved, failing no run.
- Unconfirmed is what the word table cannot tell apart (rows that share words, or `manyCauses`), known before the run; a run's refusal in other words than its entry's is an entry unused, failing it.
- Entries a run has not yet met are guesses until it does: run A's #8, #33, #38 and #61 (the plan's step 13).
- A block is named by the suite's message for it, never its id: the ids are drawn per run.

## Depends on
- `words` (`refusers`, `places`).
