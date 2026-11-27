# auth.provider2

An OAuth 2.0 / OpenID Connect provider built so that a compromised public face does not let an attacker issue tokens.

**auth.provider2 is a different product from [auth.provider](https://github.com/o3co/auth.provider).** It is built from auth.provider's modules, but its contracts, composition and version numbers are its own: auth.provider2 0.x has no relation to auth.provider 0.x or 1.x.

## What it promises

- **A new login needs the user's passkey, even when the public face (Front) is compromised.** Refresh is a time-limited delegation bound to that login.
- **A client's token needs the client's private key, even when Front is compromised.**
- Further, when a deployment adds the transparency log and the monitor, a forged issuance by a compromised Core does not pass a receiver that checks receipts, and a monitor's verdict stops that Core generation. The first release ships this guarantee's contracts; its implementation comes later.

Each promise holds under stated conditions, and the provider reports at boot which of them the running composition meets.

## Status

Under construction. Nothing is published yet: the first release, 0.1.0, is published once the design and the implementation have converged.

## Layout

- `modules/<group>/<name>`: the provider's packages, one concern each. Each module's README is its contract.
- `docs/compliance/`: the public compliance page, `deviations.md`, written from its ledger `deviations.json` (the intended deviations and strict choices a conformance run's expected failures name).
- `sdk/` (to come): the packages that run in a receiver (the login screen SDK and the relying party's verification kit). They depend only on the protocol packages, and are released with the provider at the same version.

## License

[Apache License 2.0](LICENSE)
