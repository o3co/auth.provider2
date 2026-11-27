# results

Internal module of `interop-oidf`: a run's results, each module's run read against its expected entry, in the ledger's keys.

## Responsibilities
- Reads, from each module's log and the screen role's record, the refusals it met (block, place, status, words, who answered, what the word table reads) and its FAILURE and WARNING conditions.
- Judges each module against its entry: its class, the keys observed, the keys its JARs compute, what failed it, the unconfirmed, and each review's verdict; and the run: passed, or why not.

## Not here
- The entries: `expected`. The words and what they read: `words`. Keeping a review's page: `review`'s `keptPages`, by the harness. Running the suite: `harness`. The table: `report`.

## Offers
- `judged` (an entry, a `ModuleRun`, the `Provider`, the pages' record, each review page's kept file) → `Judged`: its `Class` (`crossed`, `before-wall`, `explained`, `unconfirmed`, `skipped`, `failed`), refusals (each with what the table reads), observed and computed keys, problems, unconfirmed, reviews. `runJudged` (the entries, the runs, …) → each module, the run's problems, `passed`.
- `refusalsOf` (a module's run, the provider, its screen records) → `Met` (each refusal with its block's id); `computedOf` → the keys its pushed JARs compute.

## Invariants
- A run's refusal meets its entry's by block, place, status, refuser and words, and must read as the entry says; an entry's unmet is unused and fails; a refusal no entry names fails, unless the table reads it unconfirmed (then reported). A refusal at no place the provider has fails.
- A FAILURE or WARNING is met by its condition, each where it was logged: its keys must be shown observed by a refusal of its own block (decision 12). The result must be the entry's.
- Who refused: the harness at the resource; the Front for an answer of no words (its fixed one); else `refuserOf`, and `unknown` for words with no description.
- The screen's records go each to the one module whose visits name its key (`request_uri`, else `state`); one of none, or of two, fails the run. In order, a start (`started`, a refused start, a stop with none open) takes the next visit and opens it; a finish or a decision is its one open visit's, none taken fresh, none guessed between two. A provider's refused start or finish (`carried` kept) is a refusal there; any other stop fails the module.
- Computed keys are shown beside, never compared: `jar-typ-required` (no typ, by external-jwt's `typOf`), `jar-jti-required`, `par-jar-lifetime` (the run's PAR lifetime), and the rows of sdk-core-wire's item spellings the table reads. Not computed: `state-nonce-bound`, `prompt-none-at-par`, `rar-refused` in a form, shared rows.
- A review's verdict is the module's class as decided (crossed approved, explained, unconfirmed), one for its pages, standing on a page kept; a REVIEW with no page but released fails.
- A module that did not finish, or with no entry, fails; so does an entry no module ran. For `report`: each refusal's reading shows a block unconfirmed though its module is explained. Its files are tests'.

## Depends on
- `sdk-core-wire` (`jarClaims`, `itemsFromJar`), `external-jwt` (`typOf`); `expected`, `review`, `words`, `screen` (its record's type).
