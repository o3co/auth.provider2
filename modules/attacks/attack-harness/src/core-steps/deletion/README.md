# deletion

Unit of `attack-harness`'s internal module `core-steps`: the deletion group, K-1 to K-6.

## Responsibilities
- K-1: a delete whose continuation another key signed is forged (DEL_reg_noApproval).
- K-2: a delete approved by another subject's key, naming the victim's, is forged (DEL_reg_anySubject).
- K-3: a delete carrying a rename's continuation is forged (DEL_reg_noStage).
- K-4: a delete of a key its continuation does not name is forged (DEL_reg_noTarget).
- K-5: a delete of the last key is forged; the same deletion takes once a key is added (DEL_reg_noLast).
- K-6a: a code's bundle making a family once its approving key is deleted is forged, its start standing (DEL_reg_noRootLive).
- K-6b: a family's refresh once its root key is deleted is forged (DEL_reg_noRootLive_ref).

## Not here
- Defenses a step's refusal rests on two of, each alone, in authority-rules' tests:
  - K-2's parent and assertion ("is refused where the approving key is not live, or did not assert it, or the statement is used");
  - K-3's stage binding ("is refused for a continuation of another stage, naming another key, or of no deletion's body");
  - K-6b's DelDrop ("takes a deleted key and the families rooted in it alone") and the root key's life ("refuses a refresh's start and bundle where its family's root key is not live").

## Offers
- Nothing to import: its tests are the steps.

## Invariants
- One Core for the group, each step a person of its own.

## Depends on
- Its module's shared steps' kit.
