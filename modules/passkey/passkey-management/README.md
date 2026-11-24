# passkey-management

## Responsibilities
- Owns the kinds of a first key's evidence beside the email's token: what a kind's module is given and answers, on one contract every kind sits on.

## Not here
- Checking one kind, and its record of who holds it: its own module, which declares what it trusts and its strength to `promises`' `evidenceKinds` under the same name.
- The waits of a password: `users`' `verifyAsPart`, which the password's module asks and hands each start's end.

## Offers
- Extension point `firstKeyEvidence` (keyed by kind): a `FirstKeyEvidence` names its kind; may `prepare` what the screen needs before it makes the items; `check` (the start, the subject the identifier names or none, its own items) → `passed`, `failed`, or `absent` where its record says the subject holds none, a fault thrown, Unavailable; and may be told the start's end once it checked (`settled`).
- `FirstKeyStart`: the start's nonce, which the path owns, gives a short life and uses up before any check, and the identifier asked for. `EvidenceAnswer`; `StartOutcome`, how the path ended the start: `passed`, `failed` (its own refusals too) or `unavailable` (a kind's fault or its own).

## Invariants
- A kind answers alike, in shape and work, for a subject of none, one holding none of the kind, and one holding it: a subject of none fails. So does `prepare`, alike too for one identifier each time.
- `absent` is the kind's record saying the subject holds none; a record lost fails, and a kind asked of everyone never says it. Each answer stays in the path: the screen is answered alike.
- A kind reads only its own items, under its name in the request's map of kinds, as the screen sent them.
- `prepare` runs before the nonce is used up; `check` once for each kind after, none past the nonce's life; `settled` once for each start a kind checked, after every kind has answered, a fault among them too; one may never come, and a start not told is not passed.
- Nothing here runs a start yet: no module collects the kinds.
- The path's rule, which its body runs: the email's token is always asked, being the path's and no kind; beside it, every kind composed that does not answer `absent` passes. With no kind composed, the inbox alone passes, and the strength's output says so. One answering `absent` to every kind composed is refused, unless `inbox-only-when-absent` (off by default) is on, which declares in the strength's output that some pass on the inbox alone.

## Depends on
- `kernel`

## Vocabulary
- first key: a subject's first passkey, issued through the first key's path to a subject holding none.
- evidence kind: one way the path checks the person beside the email's token.
- start's end: how a start ended over every kind asked, which a kind with waits needs.
