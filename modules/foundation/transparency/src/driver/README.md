# driver

Internal module of `transparency`: the frame's I/O around its pure core, the `transparency` contract's implementation.

## Responsibilities
- Runs each Core event as one read and one conditional write of the frame store, and appends through the log's axis.

## Not here
- What an event writes: the internal module `frame`. The fold: `authority-rules`.

## Offers
- `transparencyOver` (the frame store, the log, the kinds, the owners, the lease) → `Transparency`.

## Invariants
- Each event reads the frame, every state owner's records and the intent's kind's records, decides with the core, and writes them in one write held to every version read: a lost race writes nothing (`moved`), and an owner's write past its lease neither (`late`).
- A Step applies `fold` once, on the state the owners' records hold, each owner mapping the result back to its records; the kind's records the end writes go in the same write.
- `send` checks the owner before the append, and a first stage's prevMismatch closes the op without a record. `rebase` re-checks on the flow taken in to its head: it moves the previous position, or closes.
- `tend` takes the flow in to its head (as the apply phase of an op it took over), then takes over an orphan its kind can resend, marks any other, or sends the abandoning op's next abandonment.
- A registration naming a record of a part not its own, or writing another count of records than it read, is a TypeError.

## Depends on
- `authority-rules` (`fold`, `emptyState`, the state's schema); the internal module `frame`.
