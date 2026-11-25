# evidence

Internal module of `passkey-management`: a start's evidence, the kinds composed taken together by the path's rule.

## Responsibilities
- Asks every kind composed of one start, takes their answers together by the path's rule, and tells each kind the start's end.
- Holds the inbox's kind, as the path declares it to `promises`, and finds the kinds composed that `promises` holds no living declaration of.

## Not here
- Checking one kind: its own module. When the start's end comes, and what the screen is answered: the path's start.

## Offers
- The package's extension point `firstKeyEvidence` (keyed by kind): a `FirstKeyEvidence` names its kind; may `prepare` what the screen needs before it makes the items; `check` (the start, the subject the identifier names or none, its own items) → `passed`, `failed`, or `absent` where its record says the subject holds none, a fault thrown, Unavailable; and may be told the start's end once it checked (`settled`).
- `evidenceOver` (the kinds composed, whether one absent on all may pass) → `ask` (the start, the subject or none, the request's items by kind) → `Asked`: `checked` (`passed`, `failed`, `unavailable`), the faults thrown, and `tell` (the start's end) → what the kinds threw telling it.
- `itemsOf` (the start's plain text as the wire carries it) → the items by kind: its password is the kind `password`'s, the one place the wire's fields become a kind's.
- `undeclared` (the kinds composed, the kinds declared) → the names composed that no living declaration holds.
- `inboxKind` (the token's lifetime, alone) → the inbox's kind: trusting `inbox`, a secret of the mail token's bits living its lifetime, `alone` where asked. The path declares it to `promises`' `evidenceKinds`: trusting `inbox`, a 256-bit secret living the token's lifetime, used once; `alone` where no other kind is composed or `inbox-only-when-absent` is on.

## Invariants
- With no kind composed, the inbox alone passes. Else every kind not answering `absent` passed: any fault comes to `unavailable`, any failure to `failed`, and one absent on every kind to `failed` unless one absent on all may pass.
- An answer of no word the contract names is the kind's fault, never a pass.
- Every kind is asked once, in the order composed, whatever another answered; a kind is handed only the items under its own name.
- `tell` tells every kind once however often called, the first call's end, a kind whose check threw among them; a kind that throws there, at once or later, is let be, as its end may never come.

## Vocabulary
- start's end: how the path ended a start, which each kind is told.
