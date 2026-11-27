# keys

Unit of `attack-harness`'s internal module `core-steps`: the keys group, K-7a to K-10r.

## Responsibilities
- K-7a: an approval of the victim's key carrying another passkey's assertion over the victim's T is forged (NO_CHAIN_CHECK).
- K-9: an approval of a T signed by the ring's earlier generation is forged on a Core of two generations (Rules023e ringAny).
- K-8b: a keyless subject's first trust of a first key never taken in is the residual, unsupported and taken (gap_first_trust); against a bad writer of the log alone, it holds no key the keys' owner takes.
- K-8a: a second first trust on the flow that now holds a key is forged, its reservation another, the first let lapse on the test's clock (Rules023e EvilWrite ft); its statements past their time, it would not take without the rule either, so the verdict alone tells the rule.
- K-7b: an approval rooted in a key the keys' owner does not hold is forged (holds).
- K-10: a first key of a creation signed for the key generation before an honest reset is forged, the one after taking (RE23_reg_noBnd); as K-8a, past its time, the verdict alone tells the rule.
- K-10r: the bad writer's own reset sent again is answered as placed, and an old one after the generation moved on is not placed.

## Not here
- A Store written outside the judgment (EvilPlant), and a stolen credential's writer: outside L0.
- Each rule alone, in its owner's tests:
  - authority-rules' chain: "is refused on a flow with a live key", "is refused for a creation signed for another key generation, read from the signed bytes", "is refused unless the key asserts the statement, and the statement is the writer generation's ring's";
  - transparency-local's judging: "judges forged a record whose root key's credential passkeys holds no key of, or holds for another subject";
  - transparency-local's reset: "answers the same instruction sent again as placed, …", "places nothing for an instruction of … key generation …".
- A key generation bound in the envelope (noBindGen): the envelope has no field for it.
- Whether an approval was taken in: a stalled answer does not tell it; transparency's frame test holds it ("takes in no Core record of an ended intent or another op: the flow waits").

## Offers
- Nothing to import: its tests are the steps.

## Invariants
- K-8b, K-8a and K-7b are one flow, its first key's evidence held back twice before the bad writer's first record; the Core's side is read once, after E2's own finish, its reservation alive.
- A Core per describe: two generations for K-7a and K-9; a test's clock for K-8; passkey-reset and the reset's signers for K-10.

## Depends on
- Its module's shared steps' kit; the package's `pattern` (the earlier generation's kid); `transparency-wire` (a reset instruction's `typ`); the login screen's SDK (a statement's challenge).
