# managing

Internal module of `passkey-management`: a passkey-manage's continuation stages, `/continue`'s `rename`.

## Responsibilities
- Has `approvals` take a sealed rename, and in its step renames the key it names for the subject that approved, then answers the list of that subject's keys as it is.

## Not here
- Opening, reading and verifying the sealing, the sequence numbers and the step's hold: `approvals`' `continueSealed`. The label's record and its rule: `passkeys`' `keyList`. The list's completion: `approvals`' `completePasskeyManage`. The fields' checks: internal module `routes`.

## Offers
- `renameStageOver` (approvals' `continueSealed` and `completePasskeyManage`, passkeys' `publicKeyOf`, `keyList`'s `rename`) → the stage `rename`: its answer the list's completion sealed, or refused, `approver` among the words (`continued` only for a call whose number was answered meanwhile).

## Invariants
- A rename goes on only while the key that approved is active under the registration it approved by (`approver`, kept so the same continuation answers it again).
- The key it names is renamed only where it is an active key of the approving subject's; any other, or a later rename's already, answers the list unchanged. Its `by` is the statement's hash, the continuation's number and the end of its record, past which none of its steps runs.
- A label the wire took and passkeys refuses, or a rename in the clear, is a fault. A ring that signs no more is unavailable, so the step runs again.

## Depends on
- `approvals`, `passkeys`, `kernel`; the package's contract.
