# guards

Internal module of `http`: the rule every server guards the routes by, matching the policies each route uses to the rules contributed, and checking the routes against the marks.

## Responsibilities
- Guards each route with the rules of the policies it uses, or finds why boot is refused.

## Not here
- What a policy decides and answers (its owner's).
- Refusing boot and applying the guards to requests (the server's, from what this gives).
- The marks' check itself (`guarantees`).

## Offers
- `guardedRoutes`, on `./server`: the routes, the rules and the marks → the routes guarded (`GuardedRoute`), or the refusals (`GuardedRoutes`): a policy with two rules (at `http.policies`); else each route using a policy with no rule; else each route that breaks what it declares (at `http.routes:<method> <path>`).

## Invariants
- A route's policies run in its order before its handler, and the first answer ends the request; a route using none is given back as it is.
- Policies match by value, and a label only names one in a report.
- A route's options are copied and frozen when it is guarded.

## Depends on
- `kernel` (freezing, the refusal's form); `http` (its contract); `guarantees`.
