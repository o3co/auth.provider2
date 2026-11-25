# chain

Internal module of `authority-rules`: Allowed(r, S), the time rules and the changes of a Core writer's record.

## Responsibilities
- Holds a Core writer's record to its kind's chain rules on its flow's state and judged prefix, before its append (the Core's local check) and after (J7).
- Gives TimeOK by the acceptance time, a record's changes (Eff(r)) and the root its chain rests on.

## Not here
- The rows around J7 and their order, and the outcome: `judgment`. The state's words and the fold: `fold`.

## Offers
- `allowed` (`Ask`) → `Allowance`; `refusalOf` (`Ask`), the first rule broken; `uncheckedOf` (`Ask`), why a client's record is unchecked; `clientOf` (`Ask`), a client's start's entry fields. `timely` (`Ask`, time). `effectOf` (`Ask`) → `Changes`. `rootOf` (`Ask`): the root's registration, or a first-trust key itself, the two told apart by shape so no registration id is taken for the other.

## Invariants
- An approval, a key change, and a start and a bundle rooted in a code or a refresh are a person's ops, on a subject flow; a start and a bundle rooted in a client (`client`) are on that client's flow alone.
- An approval: one stage; T verified by the writer generation's ring; its key live; the key's assertion over T; T unused; the envelope's statement and assertion digests the preimage's.
- A first-trust key: one stage, naming no parent or root; its evidence the creation, the screen's continuation where it carries one, the possession and the new key's assertion, in that order.
  - Creation and possession by the writer generation's ring; the creation signed for the flow's key generation (`kg`) and its subject; the continuation as a passkey-add's; the possession naming the creation's digest, the credential and the key by its thumbprint (a key `keyThumbprint` takes, of an algorithm the creation offered); the new key asserting the possession.
  - On every path (a passkey-add's too): its statements one issuer's, read from the signed bytes; the possession's reservation the record's op (P 355). The issuer is not yet the log's: once the context names it, `possessionRefusal` compares it there.
  - Its path is the signed creation's `basis`. None or `first-key`: the first-key path's, on a flow with no live key; its continuation is required once its writer carries it (Axiom 4's third step). A passkey-add's creation is no first key's.
  - `sign-up` (F1, P 358): after its T, with its continuation; T by the writer generation's ring as an authorization's; the creation for it (`evidence` T's digest) with T's E keys; on a flow with no record before it, even one that left no key.
  - A sign-up's T is used by its approval after it (its times that approval's). The key uses no mark, so one key from one T holds within its flow alone (across flows, approvals' `signUp` on the Core's side).
  - Its envelope's key change digests, the possession's and the new key's assertion's (V22): different ones are forged, and one naming none is refused (no such log exists before 0.1.0). A passkey-manage's key change has no rule yet, so is refused.
- A key a passkey-add adds (proposal 3.13's order): one stage; its evidence the passkey-add and its approving assertion, the creation, the continuation, the possession and the new key's assertion, in that order, each statement by the writer generation's ring (stricter than P 355 asks: taken at D4, P 355 to follow).
  - The approving key (`parent`) live, asserting the passkey-add, which is unused; the creation for it (`basis`, its digest), for the flow's subject and key generation, with its E keys; the screen's E_sig over `continuation.of("register", …)` of the creation and the body; the body's key the record's; no live key of the flow of its credential; the possession as a first key's; the envelope naming its digests, the possession's and the new key's assertion's.
  - It adds the key under the approving key's chain and uses the passkey-add (one key from one root); its root is the approving key's.
- A start: the first stage, not the last; of a live approval whose code is unused and was started by no code start before (any verdict; a refresh start naming it does not count), naming that approval's code digest and client (V24, A21), or of a live family at its rotation.
- A bundle: the last stage, after its op's start, naming that start and a root; never after a forged start (a forged parent's descendant); the root the start's wherever the start's preimage was read; a live approval with its code unused and the start within the code's lifetime of it, whatever the start's verdict, or a live family at its rotation; and no stage before it acceptable yet not taken.
- A noEffect: after a stage of its op that is not acceptable and taken. An abandonment: always, its family the one the abandoned op's bundle made or rotated, or none.
- A client's start and bundle: the internal module `client`'s rules, after its stage's place; a client's root is no first-trust key, so J12 is not asked of it. Its changes are none.
- TimeOK, each bound held at its edge: a client's start within its evidence's times, the evidence window on each side; an approval within T's times, a first key within its creation's and possession's, an added one within its statements', a code's start within L of its approval, a refresh within its family's lifetime, a bundle within the issue window of its start; noEffect and abandonment have none.
- An abandonment's family comes from the abandoned op's bundle entry's changes, by `fold`'s `abandonedFamily`: where the monitor could not read that bundle's preimage (J5, J6) they are empty, so the monitor names no family where the Core's intent names one (kernel-spec §6.3's contract 1 leaves this open).

## Depends on
- `transparency-wire` (the request's fields). The package's `evidence` and `fold`.
