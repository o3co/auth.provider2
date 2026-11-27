# words

Internal module of `interop-oidf`: the provider's words for the ledger's rows, and what a refusal a run saw says of them.

## Responsibilities
- Holds, for each ledger row a refusal can show, who answers it, where, its OAuth `error` and its `error_description` exactly, and the request's feature that tells a row apart from another cause answered in the same words (a DPoP header; a `request_uri` started before).
- Reads a refusal seen: the one row it shows, rows it cannot tell apart, or none.

## Not here
- Seeing a refusal and the request's features: whoever records the run's requests and answers.
- Judging a run's results by it.
- The words themselves: each product module's; the table copies them as they are answered today, and `rp`'s test holds every word to a scene's answer.

## Offers
- `refusers` and `places` (`Refuser`, `Place`): who answers a refusal and where, the lists a reader of refusals holds others to.
- `words`: the table (`Word`: the row's key, `refuser`, `place`, `error`, `description`; `dpopHeader` or `startedBefore` where a feature tells the row apart; `shared` where the words answer other causes too).
- `manyCauses`: the words that answer many causes no row names (the client's authentication), each `ManyCauses`.
- `readingOf` (a refusal `Seen`, a table, the words of many causes) → `Reading`: `observed` (one row), `unconfirmed` (rows, or none where words of many causes), or `none`.
- `wordsProblems` (a table, the ledger's keys) → why it may not be taken.

## Invariants
- A refusal is `observed` for a row only where that row's words alone fit and they are no other cause's; words that are shared, or that two rows answer alike, leave it `unconfirmed`, never a guess.
- A word names a row of the ledger, with words not empty; two rows' words that a request cannot tell apart are refused unless both say they are shared.
- A way a row shows with no refusal (`form-post-required` as the suite reads a callback's query) has no word; a row may have words at more than one place.
- Words the product answers at another place than the table names (`jarVerified`'s again at a login's start, for a JAR by value or one past `authorize`'s own lifetime) read as none: never a row by a guess.

## Depends on
- No workspace package.
