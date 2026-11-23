# judgment

Internal module of `authority-rules`: Verdict(r) by the judgment table (kernel-spec §6.1) and Outcome(r) (§6.2).

## Responsibilities
- Judges one placed record on its flow's judged prefix by the first row it meets, J0 to J13, and gives its outcome and the entry the fold and the later records read.

## Not here
- The chain rules (J7's content) and the time rules: `chain`. Waiting, retrying, the checkpoint, the deny list and the hold limit's count: the monitor's.

## Offers
- `judge` (`Reading`) → `Ruling`: the entry, the row, whether counted, the rule broken; or `wait` (`temporary`, `version`). `outcomeOf` (`Reading`, verdict).
- `Reading`, `Opening` (opened, undecryptable, missing, failing since), `Window` (b(v), b(v+1)), `Ruling`, `Row`, `FlowRecord`.

## Invariants
- J0: a monitor's, publisher's or the people's record of its role's kinds is verified and took; its changes and parent come from its body. The body must be the one its signature verified and hold to transparency-wire's `signedRecord`, else a TypeError: what does not verify is not there, for the caller to drop.
- A writer naming a kind its role does not write is forged (J2), whatever the role, without reading its body.
- J1 waits while a temporary failure lasts less than T_retry, and WaitVer while a named version's window is not given; neither gives a verdict.
- The caller gives a version's window only once it has read the publisher's shard past the record's a + ε (PubClosed): a window with no `next` then says no next version was accepted by then; one given earlier can miss J10.
- The order: J2 (kind, a second start of one approval), J3 (a key never in a set), J4 (does not decrypt, not the wire's form), J5 (damaged, lost), J6 (failing past T_retry), J7 (the chain), J8 (before b(v) − ε), J9 (an earlier stage of the op held), J10 (at or past b(v+1) + P + ε, counted), J11 (no key of the record's set), J12, J13.
- J12: a first-trust key, and a record whose root no verified confirmation before it names, are unsupported; the rest verified (J13).
- Only J10 counts toward the hold limit. The outcome: didNotTake for forged and held, by TimeOK for the rest, took for another writer's record.

## Depends on
- `transparency-wire` (the record, the verdict and outcome words). The package's `chain`, `evidence` and `fold`.
