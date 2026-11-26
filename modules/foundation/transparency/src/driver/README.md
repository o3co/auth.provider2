# driver

Internal module of `transparency`: the frame's I/O around its pure core, the `transparency` contract's implementation.

## Responsibilities
- Runs each Core event as one read and one conditional write of the frame store, and appends through the log's axis.

## Not here
- What an event writes: the internal module `frame`. The fold: `authority-rules`.

## Offers
- `transparencyOver` (the frame store, the log, the kinds, the owners, the lease) → `Transparency`. `clientTending` (a `Transparency`, the frame store): one round tending each client flow the store lists, a flow unavailable now passed over to the next round.

## Invariants
- Each event on a subject's flow, or a client's op (any other is `notSubject`), reads its unit's frame, every state owner's records (none for a client's op) and the intent's kind's records, decides with the core, and writes them in one write held to every version read: a lost race writes nothing (`moved`), and an owner's write past its lease neither (`late`).
- A client's op is decided looking on from the flow's head, sends with no previous position, takes in its own next record past any other, and is claimed or abandoned only once taken in to the head; its flow's record lists it from its decision to its end, in the same writes as its frame, which its end drops; `tend` of a client's flow tends the first 64 listed, moved to the list's back in one write before, so every listed op is reached in its turn, and returns at once for an op not open.
- What the flow holds of an op (its last stage, its abandonments, its stages for `rebase`, and for a client's op whether it is ever decided again) comes from the log's `of`; a client's op closed with nothing on the log is kept among its flow's record's closed, which `decide` refuses as `ended`. An open intent of a kind not registered here is stepped, claimed and ended by no event (`stuck`).
- A Step applies `fold` once, on the state the owners' records hold, each owner mapping the result back to its records; the kind's records the end writes go in the same write.
- `send` checks the owner before the append, and a first stage's prevMismatch, or a client's op's stage refused `abandoned`, closes the op without a record. `rebase` re-checks on the flow taken in to its head: it moves the previous position, or closes.
- What the log answers is held to `transparency-wire`'s forms: a record at `at` (the very flow and position asked, taken in as read; a record id never `__proto__`), an accepted append's or reset's answer. One off them, or one whose reading throws, is never taken in: its event is unavailable, the take-in meeting it writing nothing (steps a `tend` committed before stay; an append or reset the log already placed stays placed; on a client's flow the turn's other ops are tended first).
- A log adding a record field or a `v` needs its Cores upgraded first: until then, its records are off the form.
- `receiptOf`, on a subject's flow alone, appends after a position no head reaches: the log answers a stage it holds as first placed, before it reads the position, and refuses any other there (`unplaced`), so it never places one; an op the log's `of` holds no stage of is `unplaced` unasked, and a stage naming another op or flow is a TypeError. It reads and writes no frame.
- `applied`, on a subject's flow alone, reads as `receiptOf` does, then takes the flow in through the stage's position: each step bound in the snapshot its write is held to, checked in order sealed (`sealed`), an intent of its op of another kind (TypeError), taken in through it already (answered, writing nothing), then the next record (`stuck` only here).
  - Up to 64 steps a call (`far`); a moved or late write read again up to `kindReads` attempts (`moved`); the log not yet showing its record, `unjudged`. Its ending is the one `stepped` gives (`endingOf`), from the record its answer names (id and op), else unavailable.
  - A call costs `log.of` and one append as a read; taking S records in, uncontended, 2(S+1) frame reads and S+1 `log.at`, the last its ending's; a moved write's re-read one round more.
- `receiptOf` places nothing whatever order the log checks in, as no head is ever its previous position; a placed stage's receipt comes back only where the log checks the same id first, as transparency-wire's card promises, which every log's adapter keeps.
- `tend` takes the flow in to its head (as the apply phase of an op it took over), then takes over an orphan its kind can resend and no one took over yet, marks any other, or sends the abandoning op's next abandonment.
- A registration naming a record of a part not its own, or writing another count of records than it read, is a TypeError.

## Depends on
- `authority-rules` (`fold`, `emptyState`, the state's schema), `transparency-wire` (`schemas.record`); the internal module `frame`.
