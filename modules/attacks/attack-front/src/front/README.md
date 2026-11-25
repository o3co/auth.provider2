# front

Internal module of `attack-front`: the dishonest Front.

## Responsibilities
- Relays a role's HTTP request to the Core as its operation's frame, as an honest Front does, the source it declares its own, and answers the reply as HTTP; between them, the step's rewrite of the message and of the reply.

## Not here
- The wire's connection (core-wire's `wireClient`, given), the roles and their keys, what a step expects.

## Offers
- `badFront` (`Wire`, source): `post` (`Sent` → `Answered`), `send` (a frame of its own making), `rewrite` (`Rewrites`: each operation's message, each reply), `seen` (every frame and reply, `Relayed`).

## Invariants
- A request of no operation is `404`, one with a field the frame cannot carry `400` `invalid_request`, nothing sent; a reply `ok` is the operation's success status and JSON body, a refusal its word's status with `error`, `error_description` where the Core gave a detail, and its `Retry-After`, a rejection `502` `server_error`: as `front-relay` answers them.
- A request is given as its body's members and headers, so a body of another type (`415`) and a member that is no string are not relayed here.
- A rewrite is typed by its operation's message: it changes what a Front can, never what the frame cannot carry.

## Depends on
- `front-core-codec` (an operation's message from HTTP), `front-core-wire` (its HTTP side, the refusals' words).
