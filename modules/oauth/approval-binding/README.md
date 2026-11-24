# approval-binding

## Responsibilities
- Joins `sender-binding` and `approvals`: declares that it fills the authorization statement's `dpop_jkt`, the thumbprint of the key the client's tokens will be bound to, as the client's JAR names it ahead (RFC 9449 §10).

## Not here
- Reading the item from the JAR and building the statement: `authorize` and `approvals`. Proving the key at the token endpoint and binding the tokens to it: `sender-binding`'s kinds (`dpop`) and the code's exchange.

## Offers
- A contribution to `approvals`' `statementItems`: purpose `authorization`, item `dpop_jkt`.

## Invariants
- Composed only with both packages it joins, so a composition with no person's approval (client credentials alone) takes in no dependency of `approvals`.

## Depends on
- `kernel`, `approvals` (the extension point), `sender-binding` (the binding the item names).
