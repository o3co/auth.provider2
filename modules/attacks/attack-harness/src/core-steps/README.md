# core-steps

Internal module of `attack-harness`: the compromised Core's steps, K-1 to K-17, each from a counterexample of the formal models, each group its own unit; for its tests alone.

## Responsibilities
- Holds what the groups share: the records a bad writer makes from evidence (authority-rules' `./testing`, digests SHA-256 as the log's), a Front holding back the requests it names, the evidence a screen's held request leaves unspent (a login's, a sealed delete's or rename's, a key added's), and the request that has the Core take a flow in (a new login's finish).
- K-15 (KP_04), each group's last step over each of its Cores: every flow its bad writer placed on, read whole, holds no forged record the bad writer did not place, none held or unjudged, its forged ones as judged when placed; each placement is kept in the Core's ledger for it.
- Each step: a bad writer places a record its evidence does not hold (M) and beside it the same with the attack's one point undone, or the same shape on another approval (U); the monitor's judgment of each (M as its row expects, `forged` but for a residual or a time's outcome; U as an honest record's), and the Core's side, the new login stalling (`temporarily_unavailable`) and, for a record touching keys, the keys' owner holding what it held.

## Not here
- The Core and its ports: the package's internal module `in-process`. The roles and the world: `roles`, `world`.
- A defense checked alone, where a step's refusal rests on two: its owner's test, named in the group's card.
- The dishonest Front: never read here.
- The approving key (V30, FIX_ADD_PARENT): no step, as no end-to-end run here has a compromised Core answer the screen; its rules alone, in their owners' tests:
  - authority-rules' chain: "is refused unless the creation names the record's parent as its approving key (V30, FIX_ADD_PARENT: add_key_under_own_parent)", "is refused where the creation names another screen's keys than its passkey-add (P 355: the E keys the same)";
  - login-screen's management: "refuses a creation naming another key than the one its own assertion verifies under, before create()"; its assertion: "verifies under its own key, P-256's and Ed25519's", "is unverified under another key, of its type or the other".

## Offers
- Nothing to import: its tests are the steps.

## Invariants
- A step's evidence is all held back before the bad writer places its first record on the flow, and every record on that flow after is the bad writer's; M and U are of different ops.
- A judgment is read as the log gives it, a verdict and an outcome; no rule's reason is read.
- A forged record taken with a verdict a receiver takes stops the work: it is told, never fitted.

## Depends on
- The package's `in-process`, `world`, `roles`, `pattern` (its start's limit) and `relay`; authority-rules' `./testing`, `continuation-wire`.
