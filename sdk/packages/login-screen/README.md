# login-screen

## Responsibilities
- The login screen's SDK: what the screen runs between the person and the Core, following the screen–Core protocol (`sdk-core-wire`) and the transparency log's (`transparency-wire`).

## Not here
- What crosses the network: the screen–Core HTTP envelopes (a sealed value's encoding, each stage's request and answer, the paths) wait for the protocol's review; until then the caller hands the SDK its transport.
- The management screen's purposes (`passkey-manage`, `passkey-add`) and a continuation's signature form: they wait for the protocol's review.
- The relying party's checks: `rp-kit`.

## Offers
- Nothing yet.

## Invariants
- It depends on the provider's protocol packages alone (the sdk's guard).
- Shipped code runs in a browser: WebCrypto, no Node builtins.

## Depends on
- `sdk-core-wire`, `transparency-wire`.
