# key-changes

Internal module of `login-screen`: a key change's completion, read and shown taken (internal unit `signed-set`: a status or stateOf as its signer set signed it).

## Responsibilities
- Reads what a key change waited for, at the level the caller names, and says when it may be shown taken.

## Offers
- `keyChanges.read` (what was waited for: a possession and the new key's assertion, or a delete's `Continued`; the sealed completion; the ring, the screen keys, the issuer; the level the caller names, `L0` or `log` with every log input): the change, exactly the one waited for, under its path's purpose, a delete's read only padded to one of sdk-core-wire's buckets (else `open`).
  - For a delete the Core did not take, `kept` (`KeptDelete`): the keys as they are and why (`last`, `used`, `unknown`), from the list for the statement answered naming exactly the delete sent (else `statement` or `continued`; its assertion's hash is not read here, no assertion being given).
  - At `log` also §C.5's four: the receipt, its age, the status, the stateOf, its state read by flow-state-wire holding the key added, not the one deleted.
  - Or a refusal no fetch changes (`KeyChangeError`), or `retry` with the receipt read (`KeyChangeRetry`): the status or stateOf to fetch and give back in the checks.

## Invariants
- A key change is shown taken only once every check its level names passed. A refusal the log's objects gave (denied, the record's result, the state) stays with the change, and a status or stateOf older than one read before for it is not taken, so no older object, no source made again, nor a read of the same change beside it, undoes what was read, for as long as the page lives (a reload forgets it, with the sources).

## Depends on
- `sdk-core-wire`, `transparency-wire`, `flow-state-wire`.
- The package's `completion`, `receipt`, `hpke`, `jws`, `keys` and `bytes`; the package's `management` (`Continued`) and `first-key` (`ReadPossession`).
