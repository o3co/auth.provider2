# relay

Internal module of `attack-harness`: the Front's contract as a role uses it, and relaying as an honest Front does.

## Responsibilities
- Defines what a role sends and is answered (`Sent`, `Answered`), the wire a Front holds (`Wire`) and a Front as a role uses it (`Front`: `post`).
- Relays in three parts, as an honest Front does: a request read as its operation and message, the source the Front declares its own; frames carried on one wire, each its own id; a reply answered as HTTP. The honest relay is the three in order.

## Not here
- A change to what is relayed, frames of a Front's own and what it saw: the package's internal module `front`, which arranges these parts.
- The wire's connection (core-wire's `wireClient`, given), the roles and their keys.

## Offers
- `read` (`Sent`, source) → the operation and its message (`Read`), or the answer for a request of none; `carrier` (`Wire`) → `send`, frames in id order; `sendOrRefuse` (a carrier, an operation, its message) → the reply, or the answer for a field the frame cannot carry; `answerOf` (operation, reply) → `Answered`; `unsendable`, the answer to a request it cannot send.
- `honestRelay` (`Wire`, source) → a `Front` relaying each request as it came, beside its answer the Core's reply as the wire carried it.

## Invariants
- A request of no operation is `404`, one with a field its operation or the frame cannot carry `400` `invalid_request`, nothing sent; a reply `ok` is the operation's success status and JSON body, a refusal its word's status with `error`, `error_description` where the Core gave a detail, and its `Retry-After`, a rejection `502` `server_error`: as `front-relay` answers them.
- A request is given as its body's members and headers, so a body of another type (`415`) and a member that is no string are not relayed here.
- It reads nothing else in its package.

## Depends on
- `front-core-codec` (an operation's message from HTTP, the frame), `front-core-wire` (its HTTP side, the refusals' words).
