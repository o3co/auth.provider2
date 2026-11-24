# store

Internal module of `code-grant`: the interfaces of the places its records are kept, which the assembly wires.

## Responsibilities
- Declares the store interfaces and what they need, and the longest a redemption record lives.

## Not here
- What a record holds and its format (`codes`, `redemption-record`): a place is never shown it. Erasing and migrating them (`erasure`).

## Offers
- `codeStore`: codes by a name made from the code (`nameOf`), each created by the code for its subject (`created`, `exists`, `erased`), rewritten from the current contents, answering before and after.
- `redemptionRecords`: each redemption record by that name, for its subject (create, read, rewrite).
- `voidList`: the codes to void (add, done, go through in order, one whose handling fails staying).
- `codeStoreNeeds` (never evicted, survives a crash, never rolled back by failover, names made from a secret) and `storedRecordMaxMs`.
- Each place's optional `erase` and `migrate`: all of them or none.

## Invariants
- Every call throws Unavailable when the place cannot tell. A change reruns on a race, so it is pure; a record gone is never written back.

## Depends on
- `kernel`, `tokens` (the longest token's lifetime), `erasure-extensions` (the reports and walks of erase and migrate).
