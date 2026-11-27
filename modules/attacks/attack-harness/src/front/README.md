# front

Internal module of `attack-harness`: the dishonest Front.

## Responsibilities
- Relays a role's request as the honest relay's parts do, the source it declares its own; between reading it and answering, the step's rewrite of the message and of the reply.
- Sends frames of its own on the same wire, and keeps every frame sent and its reply.

## Not here
- Reading a request, carrying a frame, answering a reply as HTTP, and what `Sent`, `Answered` and `Wire` are: the package's internal module `relay`.
- The wire's connection (core-wire's `wireClient`, given), the roles and their keys, what a step expects.

## Offers
- `badFront` (`Wire`, source): `post` (`Sent` → `Answered`, beside the HTTP answer the Core's reply before any rewrite, none where nothing was sent), `send` (a frame of its own making), `rewrite` (`Rewrites`: each operation's message, now or once worked out, and each reply), `seen` (every frame and reply, `Relayed`).

## Invariants
- A request's message and its reply are rewritten by one setting, the step's rewrites as they stood when it came.
- `seen` keeps the frames relayed and its own as their replies come, each with the reply as the wire carried it, before any rewrite; a frame of its own goes unrewritten.
- A request whose rewrite throws `WireEncodeError` is answered as one the frame cannot carry (`unsendableOf`, its refusal's word), nothing sent.
- A rewrite is typed by its operation's message: it changes what a Front can, never what the frame cannot carry.

## Depends on
- The package's `relay`; `front-core-codec`, `front-core-wire` (the message and the operations' types).
