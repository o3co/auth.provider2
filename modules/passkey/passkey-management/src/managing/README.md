# managing

Internal module of `passkey-management`: a passkey-manage's continuation stages, `/continue`'s `rename` and `delete`.

## Responsibilities
- Has `approvals` take a sealed rename, and in its step renames the key it names for the subject that approved, then answers the list of that subject's keys as it is.
- Has `approvals` take a sealed delete, and in its step deletes the key it names through the key change's writer, answering its key change, or the list naming why not.

## Not here
- Opening, reading and verifying the sealing, the sequence numbers and the step's hold: `approvals`' `continueSealed`. The label's record and its rule: `passkeys`' `keyList`. The list's completion: `approvals`' `completePasskeyManage`. The fields' checks: internal module `routes`.

## Offers
- `deleteStageOver` (approvals' `continueSealed` and `completePasskeyManage`, the key change's `remove` and `removed`) → the stage `delete`.
- `renameStageOver` (approvals' `continueSealed` and `completePasskeyManage`, passkeys' `publicKeyOf`, `keyList`'s `rename`) → the stage `rename`: its answer the list's completion sealed, or refused, `approver` among the words (`continued` only for a call whose number was answered meanwhile).

## Invariants
- A rename goes on only while the key that approved is active under the registration it approved by (`approver`, kept so the same continuation answers it again).
- The key it names is renamed only where it is an active key of the approving subject's; any other, or a later rename's already, answers the list unchanged. Its `by` is the statement's hash, the continuation's number and the end of its record, past which none of its steps runs.
- A label the wire took and passkeys refuses, or a rename in the clear, is a fault. A ring that signs no more is unavailable, so the step runs again.

- A delete placed already, by a first run or another replica, is answered first as the log judged its own record (`removed`): its key change with its first receipt where it took (applied and settled first), `ended` (kept) where it did not, thrown while unjudged; whatever changed since, a key that deleted itself too. No call decides a deletion past its hold, so a number answered `last`, `used` or `unknown` never deletes after.
- Else it is deleted (the writer's `remove` of a `DeletedKey`, its op one per number; the approving key as it approved read in its decision, `approver`), its answer the key change with the log's receipt; one not taken (`last`, `used`, `unknown`) is answered with the list naming why, at the same padded length, so the Front learns neither which key nor whether nor how many. `expired`, `approver` and `ended` are refused. Timing still tells a deletion, which waits on the log, from a refusal.
- One answer per number, the first kept by `continueSealed`: the same continuation again gets it, never a later one. Passing failures are thrown, never kept. A step that keeps throwing holds that statement's later numbers to its record's end.
- Deleting the approving key ends that passkey-manage: its later continuations are `approver`; the screen asks another key's approval to list again. One passkey-manage deletes one key (its mark).

## Depends on
- `approvals`, `passkeys`, `kernel`; the package's contract.
