# approval

Internal module of `passkey-management`: a passkey-add's approval (§3.13's registration, step 1, and the creation of step 2), and a passkey-manage's (the list of keys).

## Responsibilities
- Signs a passkey-add or a passkey-manage for the screen and uses it by the approving key's assertion; answers a passkey-add's completion carrying the creation it bases, made for the subject that key holds, and a passkey-manage's listing that subject's keys.

## Not here
- The statement's signing, record, use and completion: `approvals`. The creation's items: internal module `creation`. The routes and the wire's words: internal module `routes`. The registration that follows: internal module `registration`.

## Offers
- `approvalOver` (approvals' `issue`, `use`, `passkeyAddOf`, `completePasskeyAdd` and `completePasskeyManage`, passkeys' `publicKeyOf`, users' `contactsOf`, the creation's making, the deployment's name) → `start` (purpose, the screen's keys, the key it is counted by) → the statement, or refused; `finish` (statement, assertion) → the completion sealed to the screen, or refused. Each refusal's reason is for the log alone.

## Invariants
- A finish takes its path by the purpose its statement names, which approvals checks: a passkey-manage's answers the list `approvals` keeps first, and makes one only while the key that approved is active under the registration it approved by (`approver`).
- A finish answers the completion `approvals` keeps first, whatever has lapsed since, and goes no further for a statement of another purpose: an authorization's statement and assertion sent here are neither used nor base a creation.
- A subject holding the most keys passkeys lets it gets no creation (`full`), before one is asked of the person.
- A creation is made only for the subject of the key that approved, while that key is active under the registration it approved by: one removed since, or its credential registered again, bases none.
- The account it shows is `accountOf` the subject's contacts: the address verified last masked, else the deployment's name and a short mark of the subject.
- A store or ring that cannot answer now, a count reached or a signing busy, is unavailable: nothing is kept, and the same finish is asked again.
