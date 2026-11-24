# chain

Internal module of `authority-rules`: Allowed(r, S), the time rules and the changes of a Core writer's record.

## Responsibilities
- Holds a Core writer's record to its kind's chain rules on its flow's state and judged prefix, before its append (the Core's local check) and after (J7).
- Gives TimeOK by the acceptance time, a record's changes (Eff(r)) and the root its chain rests on.

## Not here
- The rows around J7 and their order, and the outcome: `judgment`. The state's words and the fold: `fold`.

## Offers
- `allowed` (`Ask`) → `Allowance`; `refusalOf` (`Ask`), the first rule broken. `timely` (`Ask`, time). `effectOf` (`Ask`) → `Changes`. `rootOf` (`Ask`): the root's registration, or a first-trust key itself, the two told apart by shape so no registration id is taken for the other.

## Invariants
- An approval, a key change, a start and a bundle are a person's ops, on a subject flow.
- An approval: one stage; T verified by the writer generation's ring; its key live; the key's assertion over T; T unused; the envelope's statement and assertion digests the preimage's.
- A first-trust key: one stage, on a flow with no live key; creation and possession by the writer generation's ring, the creation signed for the flow's key generation (`kg`) and its subject, the possession naming the creation's digest and the credential, and the key by its thumbprint (a key `keyThumbprint` takes, a caller without it taking none, of an algorithm the signed creation offered) or by its uncompressed P-256 point's digest; the new key asserting the possession.
- A start: the first stage, not the last; of a live approval whose code is unused and was started by no code start before (any verdict; a refresh start naming it does not count), or of a live family at its rotation.
- A bundle: the last stage, after its op's start, naming that start and a root; never after a forged start (a forged parent's descendant); the root the start's wherever the start's preimage was read; a live approval with its code unused and the start within the code's lifetime of it, whatever the start's verdict, or a live family at its rotation; and no stage before it acceptable yet not taken.
- A noEffect: after a stage of its op that is not acceptable and taken. An abandonment: always, its family the one the abandoned op's bundle made or rotated, or none.
- TimeOK, each bound held at its edge: an approval within T's times, a first key within its statements', a code's start within L of its approval, a refresh within its family's lifetime, a bundle within the issue window of its start; noEffect and abandonment have none.
- An abandonment's family comes from the abandoned op's bundle entry's changes, by `fold`'s `abandonedFamily`: where the monitor could not read that bundle's preimage (J5, J6) they are empty, so the monitor names no family where the Core's intent names one (kernel-spec §6.3's contract 1 leaves this open).

## Depends on
- `transparency-wire` (the request's fields). The package's `evidence` and `fold`.
