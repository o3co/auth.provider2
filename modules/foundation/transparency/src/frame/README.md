# frame

Internal module of `transparency`: the intent frame's pure core (kernel-spec §5.1; the models `Step023` and `RegAbandon023`).

## Responsibilities
- Reads a stored frame, holds the owner rule, and answers the frame each Core event writes, or why it writes none.

## Not here
- Reading and writing, the log and the fold: the internal module `driver`.

## Offers
- `frameOf`, `Frame`, `Intent`, `At`, `Taken`, `Written`, `End`, `Ending`, `Refused`; `sealed`, `intentOf`, `isOpen`, `isOwner`, `isOrphan`.
- `decided` (KE-C01), `closedByOwner` and `rebased` (the owner's KE-C02), `stepped` (KE-C04 with the end-of-intent table), `marked` (KE-C14), `takenOver` (KE-C10), `abandonStage` (KE-C09), `whileClosed`.

## Invariants
- Pure: a frame, who reads it at which store time, and the event's input in; the next frame, or a refusal, out. An owner's write carries `ownerUntil`, its last store-clock ms before the lease ends.
- KE-C01 decides only on a frame sealed by the reader's generation, taken in to the log's head, with no open intent, and never an op whose last stage the flow holds, as the caller read the log.
- A Step moves one position. Another writer's record changes no intent. A Core record of no open intent, or of another op, is taken in by no one. A live owner's record waits for it, its last stage for its apply phase.
- The end table: a start changes nothing; a live owner's last stage ends its op done or closed; a bundle left alone turns abandoning, keeping the family `abandonedFamily` names; any other last stage ends alike, owner or not; a verified abandonment closes, a held one changes no intent. A noEffect ends its op not taken, unless held.
- Marking and taking over claim an orphan alone; a bundle is never taken over; an abandonment goes for an abandoning op alone, after the head the same read shows, its attempt one past the op's abandonments on the flow.

## Depends on
- `authority-rules` (its types, the changes' schema, `abandonedFamily`), `transparency-wire` (`opIds`), `zod`.
