# report

Internal module of `interop-oidf`: a run's report, its results as tables in the ledger's keys and words.

## Responsibilities
- Writes, from a run judged, the ledger and the scene's differences from the pattern, the report as Markdown: its head (plan, pin, passed or why not, the classes, the explained and before-wall modules refused at PAR on a key observed there, and what a passed run then is, what the run cannot show), how to read it, and four tables joined by test and key.

## Not here
- Judging the run: `results`. The ledger's rows: `deviations`. The words and their names: `words`. The differences: the scene's. Writing the file and running the suite: `harness`.

## Offers
- `reportOf` (`ReportInput`: the run, plan, pin, differences, `runJudged`'s output, the ledger) → the Markdown.
- `cannotShow`: what each run gives no evidence of, by its name.

## Invariants
- The tables: each module (variant by label, result, class, keys observed and computed, the unconfirmed no entry names, the reviews' verdicts); each refusal and condition, block by block in the log's order by its id, outside every block last; the ledger's rows the run names, in its order, each with how it is named (observed, computed, unconfirmed, a condition's); each computed key's harness cases (`words`' `wordName`) and words, what tells them apart beside.
- It judges nothing: what it shows is what `results` decided. Only an observed key explains; the head says what passing means and what the run cannot show, and the notes how each class and key is read. A review's verdict is the harness's own record.
- Every cell is one line (CR, LF, CRLF), a `|` escaped and no HTML. Its files are tests', as `results`' are.

## Depends on
- `results` (its types), `deviations` (`Deviation`), `words` (`words`, `wordName`).
