# review

Internal module of `interop-oidf`: a module's review, the pages its result REVIEW stands on, and the harness's verdict of each.

## Responsibilities
- Reads, from a module's log, each page a condition asked reviewed, in the state the suite left it: filled by its browser (the page's source), an image uploaded, open, or released (the module ended by its callback, the placeholder cleared).
- Keeps each filled page and image in the run's files, and records the verdict it is told for each.

## Not here
- Which verdict a page has: `results`, by the module's expected entry and the screen role's record. Filling a page: the suite's browser, by the run's configuration (`harness`).

## Offers
- `reviewPagesOf` (the module, its log) → `ReviewPage`s: the test instance, the condition (`src`), its message and block, its `PageState`, and what fills it (the page's source, type and the pattern waited for, or the image).
- `keptPages` (the pages, a directory) → each kept page's file (its extension by its type), none open or released. `reviewed` (a page, a `Verdict`, why, its file) → `Reviewed`.

## Invariants
- A verdict is the harness's own record beside the suite's REVIEW, never the suite's: its API has no call that gives a REVIEW a verdict. `approved` and `explained` stand on a page kept alone; `unconfirmed` is left unapproved, failing no run; `unmatched` fails it.
- A page the browser filled is kept on the log entry of the condition that asked (the suite's images list omits it), so the log is the one source read.
- A page's file names its test instance and condition, in letters, digits and `-`; a name taken is refused, never written over. A REVIEW that names no condition refuses the log.

## Depends on
- No workspace package.
