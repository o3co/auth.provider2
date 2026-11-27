# codes

Unit of `attack-harness`'s internal module `core-steps`: the code and client group, K-11 to K-13, K-16, K-17.

## Responsibilities
- K-11: a code's start naming another code or client than its approval is forged, the approval's own taking; approval 1's honest start after it is its code's second exchange (V24 (3)).
- K-12: a start and its bundle with no approval are forged, an approval's taking; two approvals of one code are not forged (C-7).
- K-17: a bundle naming another approval as its root than its start's is forged, its start taking, the one rooted in its own taking (C-6, another root).
- K-16: past the code's life a start does not take and its bundle is forged; past the issue window a bundle does not take, on a test's clock (BundleEscape023's times).
- K-13: on a client's own flow, the log refuses a stage of an abandoned op (`abandoned`) and a start using another start's evidence element (`evidenceUsed`); the others are verified, and the client's next token is issued (ClientFlow023).

## Not here
- Each rule alone, in its owner's tests:
  - authority-rules' chain on a start: "refuses a start naming another code or client than its approval's record, or naming none", "refuses a second start from one approval, whatever the first one's verdict", "refuses a start of an approval that is not live, or at the op's last stage", "allows a start from each of two approvals naming one code";
  - authority-rules' chain on a bundle: "refuses a bundle with no start of its op before it, or naming another start or root", "refuses a bundle whose start came after the code's lifetime, whatever the start's verdict", "refuses a bundle after its start was judged acceptable but did not take", "holds a code's start to its lifetime, a refresh to its family's, a bundle to the issue window";
  - transparency-local's log: "refuses, on a client's flow, a stage of an op whose abandonment it placed, …", "refuses a client's start naming an evidence element a start of its flow named, …".
- An earlier version's start (J10) and a held start (J5, J9): the local log has no version's window; authority-rules' judgment tests hold them.

## Offers
- Nothing to import: its tests are the steps.

## Invariants
- A Core per describe: the codes', one on a test's clock for K-16, one with a signed registry's client for K-13.
- A client's flow does not stall: its driver passes over another op's records.

## Depends on
- Its module's shared steps' kit; the package's `in-process` (the Core and its ports), `world` (the provider), `pattern` (a signed registry's client) and `roles` (the machine client); `transparency-wire` (a token's digest input).
